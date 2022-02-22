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



 我对比一下吧，xtls的源码在 github.com/xtls/go
 
 在xray的源码中，transport/internet/xtls/xtls.go 文件里，引用了 github.com/xtls/go 

 
 xtls是使用了go的 crypto/tls 的源码 conn.go 作为蓝本
 https://github.com/XTLS/Go/blob/main/conn.go

把它下载下来，用 diff命令比较一下与go官方文件的异同

1. xtls把 conn改成了 Connection，这里目前的疑惑是，外界有需要这个conn的地方吗？
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

根据后面的分析，DirectIn 和 DirectOut 是 “判断完成、该连接使用xtls” 的标志，在 Read 和 Write方法里会用到。

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

后面代码 有判断 `c.vers == 772`,772就是指 tls v1.3 ，这里显然说明只有 tls v1.3 才会使用 xtls; 他不使用VersionTLS13 常量是个败笔。

后面判断 23 3 3 后 会设置 c.total 和 c.ic; 后面会根据 c.total 以及某条件，设置 c.fall = true，然后打开 c.DirectPre 开关。

值得注意的是，c.fall,  c.total 和 c.ic 只在这一段代码里使用。

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

看来还是判断tls 1.3

c.taken 后，它会遍历数据的每一个字节；c.index 和 c.skip 初始值都为0，首先找值为23的字节，找到的话，index变为1，之后找3，index变为2，继续找3，index变为3，之后找<=66的值，index变为4，之后计算 c.skip的值，值为19的话，设 c.maybe = true

然后c.skip就不为0了，在下一个字节时，进行 c.skip 判断。操作一下 c.skip 后，无论skip <0 与否，都会控制整个for循环；只有在 c.first 时，才有可能打开 c.DirectOut开关。

c.skip < 0 的话，无论c.first判断如何，判断后都会continue循环；然后会依据 c.skip 来设置 i 的值，然后设 c.skip = 0；

在 c.first时，i的值会传给f，然后 还要调用一次 `c.writeRecordLocked(23, data[:f])`,  然后 关闭c.first,  打开  DirectOut开关

如果 c.skip >=0 ，若 c.first 则会 在  c.skip 为0 时，关闭c.first,  打开  DirectOut开关，然后 goto normal， 否则会结束整个循环, 


5. Write 方法 的首行，添加了 `if c.DirectOut {` 代码段

具体而言，他经过一些判断后，舍弃了 后 31 字节的数据，只write前面的数据

6. Read 方法首行，添加了 `if c.DirectIn` 和 `if c.DirectPre` 的代码段

在 c.DirectIn 时，直接从Connection中读取；在 DirectPre 时，依次从 input ， rawInput，和 Connection 读取，读取到任意一个后就会直接返回。

8. Close 方法的 首行，添加了 `if c.DirectOut` 代码段；在DirectOut时，不加额外措施，直接close





## 关于xray的安全问题

经理了上面分析后，xray的安全问题大概就清楚了。对比源码，再查看下面两个issue，就发现安全问题事实存在。

tls伪造攻击（21年1月）：
https://github.com/XTLS/Go/issues/12

可以被检测（21年9月）：
https://github.com/XTLS/Go/issues/16

>This makes the detection of XTLS unambiguously accurate

与xtls的issue16相关的 xray的 中文讨论issue https://github.com/XTLS/Xray-core/issues/814

## 关于 xray的流控

大概分下面三种

1. xtls-rprx-origin
2. xtls-rprx-direct
3. xtls-rprx-splice

据说上面的 23 3 3 判断是用在origin上的？？

然而，根据上文的探索，请大家在 conn.go 文件中搜索 `if c.DirectMode {`，就会发现direct模式是在 23 3 3 判断之后发生的。

也就是说， 无论是 origin 还是 direct， 都是依赖于 最基础的 客户数据分析。

splice就不用说了，和服务端没关系，属于客户端实现，实际上splice在 conn.go里没有体现出来，因此 splice是与 origin, direct 无关的一种流控；（按我的思路，它算不上流控，我认为只有在conn.go 里体现到的才叫流控）


## xray 的 legacy

不过它真的毫无价值了吗？应该也不是，因为除了这个以外，rprx还是实现了 ReadV 增强， splice等。那些功能还是有价值的。

不过 v2ray里也是有 readv的，所以也不清楚xray的那个readv和这个是什么关系
https://github.com/v2fly/v2ray-core/commits/3ef7feaeaf737d05c5a624c580633b7ce0f0f1be/common/buf/readv_reader.go

关于splice
https://v2xtls.org/xray%e5%8f%91%e5%b8%831-1-2%e7%89%88%e6%9c%ac/

# 话外

总之，关于 23 3 3的判断，我只想说，23333
