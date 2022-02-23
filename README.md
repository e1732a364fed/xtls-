# xtls 小小思考


## xray到底什么原理？

xtls从来没有人仔细解释过，唯一的解释来自rprx, 他还故意使用不同的协议，导致了分家事件；

他对xtls原理的解释：
https://github.com/RPRX/v2ray-vless/releases/tag/xtls

>1.  从第二个内层 TLS data record 开始，数据不二次加解密，直接转发，且从外面看还是一条连贯的普通 TLS。
>2.  Write 和 Read 妥善处理非预期数据和中间人攻击等，对任何干扰的反应与普通 TLS 表现一致。
>3.  服务端无法被主动探测出差异：VLESS 在验证 UUID、该用户请求且可以用 XTLS 后才会开启它的特殊功能。

看它的说明，似乎就是说，如果客户端经由代理申请了一个tls握手后，xtls会直接利用这个客户端已经加密好的部分，直接发送到 服务端，而不是再包一层加密；这样的话，实际上xtls几乎什么也没做，可以说对cpu的加密解密开销减少了100%

后来我想起来了，就是说，如果 xtls直接传输未知数据的话，效果是和 tls是一样的；比如，如果使用xtls 来访问telegram，因为telegram 的加密协定称为MTProto，并不是https，那么xtls就和tls没区别。

如果使用xtls 浏览https网页的话就不一样了，因为此时 xtls 内部传输的不是一般数据，而是另一层 tls；那么xtls显然就是为解决这个问题而诞生的。


## 源码分析

 我对比一下吧，xtls的源码在 github.com/xtls/go
 
 在xray的源码中，transport/internet/xtls/xtls.go 文件里，引用了 github.com/xtls/go 

 
 xtls是使用了go的 crypto/tls 的源码 conn.go 作为蓝本
 https://github.com/XTLS/Go/blob/main/conn.go

把它下载下来，用 diff命令比较一下与go官方文件的异同

1. xtls把 conn改成了 Connection，外界有需要这个conn的地方吗？确实用到了，在 https://github.com/XTLS/Xray-core/blob/7dcf08c5ef21b7e48dc8753af171cde5c99d1bd9/proxy/vless/inbound/inbound.go#L459
2. 多了下述字段

```go
DirectMode bool
DirectPre  bool
DirectIn   bool
DirectOut  bool

RPRX bool
SHOW bool
MARK string

ic, oc int

fall  bool
total int
count int

taken bool
first bool
index int
cache byte
skip  int
maybe bool
```

已经知道的是，这个 SHOW 只是用于打印错误或者debug信息，MARK只是针对该连接的作者可以自定义的一个标志，RPRX代表使用xtls与否。

根据后面的分析，DirectIn 和 DirectOut 是 “判断完成，且该连接使用xtls 的 direct 流控” 的标志，在 Read 和 Write方法里会用到。

3. 在 readRecordOrCCS 中发生了较大改变，具体是 `// Process message.`注释的下面
具体来说，他把 原先的下述代码

```go
data, typ, err := c.in.decrypt(record)
if err != nil {
	return c.in.setErrorLocked(c.sendAlert(err.(alert)))
}
```

替换为了长达70多行的代码，其中有很多关于 `c.fall`的判断。

原来默认就会decrypt，而这里的话，只有在 下述条件成立时才会 decrypt

```go
if !c.fall || typ != 23 || n == 19 {
	data, typ, err = c.in.decrypt(record)
}
```

`typ==23` 实际上是判断是否为 recordTypeApplicationData 类型（见common.go，一共四个类型，从20 - 23，分别是 ChangeCipherSpec，Alert，Handshake，ApplicationData ）他不使用该常量是败笔。

这里 19 显然是魔数，根据 https://github.com/XTLS/Go/issues/8 

>19 是 TLSv1.3 alert 消息的常见密文长度，这里认为它可能是TLSv1.3 的 alert

后面代码 有判断 `c.vers == 772`,772就是指 tls v1.3 ; 他不使用VersionTLS13 常量是个败笔。

后面判断 23 3 3 后 会设置 c.total 和 c.ic; 后面会根据 c.total 以及某条件，设置 c.fall = true，然后打开 c.DirectPre 开关。

值得注意的是，c.fall,  c.total 和 c.ic 只在这一段代码里使用。

同时，如果c.fall后，typ == 23 (即此时认为这是正常数据），则会 c.in.incSeq()， 表示收到了这个record，（即未经过decrypt直接接受了这个record）。

4. writeRecordLocked 方法 发生了较大改变, 插入了近140行代码

具体而言，它把原来代码的部分打上了一个 normal 标签，然后在首部判断，不符合条件就会跳转回原代码

```go
if !c.RPRX {
	goto normal
}
```

然后他的代码部分判断了很多 `c.taken`

c.first，c.taken，c.oc，c.skip 都只在这部分使用。

这里，只有 c.taken 才表示 属于需要xtls处理的部分；只有在 type为23时，且 data 前面是 23 3 3 时， 才有可能 c.taken 设为true

这个 23 3 3 是什么情况？

根据
https://halfrost.com/https_record_layer/

> **TLS 1.3 中的 additional_data 中的 2 个参与计算的字段值是固定死的(opaque_type = 23、legacy_record_version = 0x0303)**。

这个还可以参考 RFC标准： https://datatracker.ietf.org/doc/html/rfc8446  

总之还是判断tls 1.3

仔细分析，首先 默认 c.RPRX 标志是打开的，true，然后，在 `if !c.taken && !c.first && typ == 23 && l >= 5 {` 时，如果 xtls协议使用的是 tls1.3协议，则继续判断，否则则直接将 c.RPRX 标志关闭。继续判断的部分，可以理解为，如果 内部包里，有连续十个都不满足 一定条件，则会	 关闭 c.RPRX 开关。若10个以内有一个满足条件，则设 c.taken 为true。

也就是说，如果xtls协议使用的是 tls1.1, 和 tls1.2，就少了一步额外检查；如果 xtls协议使用的是 tls1.3，则要检查至多十遍内部包的数据头。


c.taken 后，它会遍历数据的每一个字节；c.index 和 c.skip 初始值都为0，首先找值为23的字节，找到的话，index变为1，之后找3，index变为2，继续找3，index变为3，之后找<=66的值，index变为4，之后计算 c.skip的值，值为19的话，设 c.maybe = true

然后c.skip就不为0了，在下一个字节时，进行 c.skip 判断。操作一下 c.skip 后，无论skip <0 与否，都会控制整个for循环；只有在 c.first 时，才有可能打开 c.DirectOut开关。

c.skip < 0 的话，无论c.first判断如何，判断后都会continue循环；然后会依据 c.skip 来设置 i 的值，然后设 c.skip = 0；

在 c.first时，i的值会传给f，然后 还要调用一次 `c.writeRecordLocked(23, data[:f])`,  然后 关闭c.first,  打开  DirectOut开关

如果 c.skip >=0 ，若 c.first 则会 在  c.skip 为0 时，关闭c.first,  打开  DirectOut 开关，然后 goto normal， 否则会结束整个循环, 


5. Write 方法 的首行，添加了 `if c.DirectOut {` 代码段

具体而言，他经过一些判断后，舍弃了 后 31 字节的数据，只write前面的数据

6. Read 方法首行，添加了 `if c.DirectIn` 和 `if c.DirectPre` 的代码段

在 c.DirectIn 时，直接从Connection中读取；在 DirectPre 时，依次从 input ， rawInput，和 Connection 读取，读取到任意一个后就会直接返回。

8. Close 方法的 首行，添加了 `if c.DirectOut` 代码段；在DirectOut时，不加额外措施，直接close

## 总结 xtls的原理

请注意 ` typ == 23 && l >= 5` 和 `if c.vers == 772 {` 这两片代码，分别在 readRecordOrCCS 和 writeRecordLocked 各出现了一次

https://halfrost.com/https_record_layer/

>在 TLS 1.2 规范中，高层协议有 4 个，分别是 change_cipher_spec、alert、handshake、application_data。在 TLS 1.3 规范中高层协议也有 4 个，分别是 alert、handshake、application_data，heartbeat。

https://datatracker.ietf.org/doc/html/rfc5246

> change_cipher_spec(20), alert(21), handshake(22),application_data(23)

也就是说，23 代表 application_data， 这个 tls1.2 和 1.3都是一样的

根据
https://halfrost.com/tls_1-3_record_protocol/

tls1.2标准
https://datatracker.ietf.org/doc/html/rfc5246

tls1.0标准：
https://datatracker.ietf.org/doc/html/rfc2246

tls1.2和 1.3的 后面 两个数都是 3,3；而tls1.0的 后面两个数是 3，1； 也就是说，23 3 3 的判断是针对 tls1.2或者tls1.3的；




## 关于xray的安全问题

经理了上面分析后，xray的安全问题大概就清楚了。对比源码，再查看下面两个issue，就发现安全问题事实存在。

tls伪造攻击（21年1月）：
https://github.com/XTLS/Go/issues/12

可以被检测（21年9月）：
https://github.com/XTLS/Go/issues/16

>This makes the detection of XTLS unambiguously accurate

与xtls的issue16相关的 xray的 中文讨论issue https://github.com/XTLS/Xray-core/issues/814




### 无限循环攻击？



#### 可以利用的代码部分

关注conn.go代码 1107行 至 1144行

这里是for循环，只要 c.skip == 0, 就会无线循环下去

如果数据是 23 3 3 0 0 23 3 3 0 0 23 3 3 0 0 ... 呢，是不是就触发了无限循环？


似乎 数据为  23 3 3 0 0 23 3 3 0 0 23 3 3 0 0  这种结构的，就会导致长循环。数据有多长，循环就会执行多少遍

那这个攻击也太方便了，1kb的流量不算啥，但是循环1000次开销可不小

我简称：233攻击

如果1MB的数据就不得了哦，循环一百万次

不过这个是在Write里的循环，也就是说，要想办法给 xtls服务器的 Write函数提供这么一段独特的数据；

因为xtls用于代理，所以xray 会读取 https服务器的真实数据，然后 用 Write函数 发送到客户端。 那么我们只要保证 https服务器的 加密https流量的数据实际上是伪造的就可以了，这个也不难。

#### 攻击情形举例

比如如果一个机场用了vless+xtls，然后我买了这个机场，我知道了vless的密码；然后我感觉这个机场不好用，我就决定攻击它的vless服务器；

我架设一个独特的https网站，对任何来的连接都进行真实tls握手，但是发送的 record 数据是经过伪造的 23 3 3 0 0 23 3 3 0 0 循环 的数据

然后我给这个独特的https网站加一个域名，比如 fake.https.com

然后我打开使用 该机场vless订阅 的 xray客户端，然后打开浏览器，输入 fake.https.com

这样机场的 xtls服务器就会收到 连接 fake.https.com 的指令，然后 我们的 fake.https.com 握手成功后，就会向 xtls发送特殊数据，然后就会触发 xtls服务器的超长循环，达到攻击目的。

#### 不持有uuid情况下的攻击

不一定需要知道机场密码才能进行攻击

可以做一个钓鱼网站，主题可以与科学上网相关，然后只要访问该网站的人使用了 xtls，那他的服务器就废了

具体来说，比如，可以写一个博文，写 xtls 如何如何好，然后给个钓鱼链接，说：“使用 xtls 的同学可以看看下面文章”等等，然后不就可以精准打击了

而且钓鱼的页面甚至可以是有效的，因为html文件可以在一个正常的服务器上提供，然后html里可以放一个自动加载的外链，比如img 标签，也是一样会执行攻击

这样的话，可以在每一条博文里都加一个这种img标签，这样你只要访问任意一个文章，都会爆。

#### 小白们的误区

有人评论说只要两端都开启tls1.3就可以防止问题？ 请问你怎么想的？甚至 23 3 3 攻击就是在攻击 tlsv1.3特征（Write 内部 tlsv1.3数据时），总之和开不开tls1.3没关系，能不能读题。

TLS1.3 无法指定加密套件而已，而我们的 2333攻击 攻击的不是握手阶段，而是第一个数据阶段，还是审题啊！那个 “23” 我不是说了吗，是 recordTypeApplicationData，这就是数据的意思。



## 关于 xray的流控

大概分下面三种

1. xtls-rprx-origin
2. xtls-rprx-direct
3. xtls-rprx-splice

### 关于 xtls/go的 issue 12

据说上面的 23 3 3 判断是用在origin上的？？

然而，根据上文的探索，请大家在 conn.go 文件中搜索 `if c.DirectMode {`，就会发现direct模式是在 23 3 3 判断之后发生的。

也就是说， 无论是 origin 还是 direct， 都是依赖于 最基础的 客户数据分析。

splice就不用说了，和服务端没关系，属于客户端实现，实际上splice在 conn.go里没有体现出来，因此 splice是与 origin, direct 无关的一种流控；（按我的思路，它算不上流控，我认为只有在conn.go 里体现到的才叫流控）

具体说，就是说 issue12认为origin模式下才有问题；而实际上根据 23 3 3的判断，我认为任何情况下都是可能被攻击的，这个我实在是小白，搞不懂，总之这就是我目前的理解。我不管rprx咋回复的，反正代码里就是如此。

rprx说：

>Direct 其实并不需要魔改 TLS 库就可以实现，它不需要读过滤，甚至传输 TLSv1.3 时连写过滤都不需要，非常简洁、高效

但是有这样的实现吗？xray不还是在使用 xtls/go 包吗？ 只要使用这个过时的包，那么direct就时时会遭受 tls v1.3 过滤所带来的问题。

direct模式和 origin模式都是用 xtls/go 的证据
https://github.com/XTLS/Xray-core/blob/e93da4bd02f2420df87d7b0b44412fbfbad7c295/proxy/vless/inbound/inbound.go#L445

xray使用 的 xtls/go 包的证据
https://github.com/XTLS/Xray-core/blob/e93da4bd02f2420df87d7b0b44412fbfbad7c295/go.mod#L19

## xray 的 legacy

不过它真的毫无价值了吗？应该也不是，因为除了这个以外，rprx还是实现了 ReadV 增强， splice等。那些功能还是有价值的。

### ReadV

不过 v2ray里也是有 readv的，所以也不清楚xray的那个readv和这个是什么关系
https://github.com/v2fly/v2ray-core/commits/3ef7feaeaf737d05c5a624c580633b7ce0f0f1be/common/buf/readv_reader.go

后面我仔细查看了，是 rprx把自己的readv代码 提交了一个 pull request, 然后merge到了 v2fly的代码里
https://github.com/v2fly/v2ray-core/pull/388

但是因为 v2fly 不使用 xtls，所以没用到。见 proxy/vless/inbound/inbound.go 文件的   `(h *Handler) Process` 函数的 `postRequest` 变量定义部分的 两个库的对比

https://github.com/RPRX/v2ray-vless/blob/master/proxy/vless/inbound/inbound.go#L448

https://github.com/v2fly/v2ray-core/blob/master/proxy/vless/inbound/inbound.go

### Splice

关于splice
https://v2xtls.org/xray%e5%8f%91%e5%b8%831-1-2%e7%89%88%e6%9c%ac/



# 话外

总之，关于 23 3 3的判断，我只想说，23333

我甚至遐想，可能rprx就是发现这两个issue不好解决才消失的。哈哈，rprx，你生气了就出来啊，你出来对大家都是好事
