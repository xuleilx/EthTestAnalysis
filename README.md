# 以太网报文分析工具
## 设计灵感
基于这样一种假设，按照TC8的Spec的要求，Tester和DUT发送的报文序列和主要内容（比如元语，TCP的flags）都是固定的。如果获取到标准报文，通过对比标准报文就能发现哪一方出错。通过本工具，可以帮助测试、开发快速发现哪一帧报文有问题。
## 设计思路
- 制作标准报文，获取以往项目的报文数据,必要时修改报文
- 过滤有效报文，通过port，或者tcp和someip协议过滤(可能有干扰数据)
- 对比标准报文
  * Check someip还是tcp协议
  * Check someip的ServiceID和MethodID
  * Check tcp flags. SYN，ack，PSH…
  * Check 窗口大小？
- 生成报告，指出哪一帧有问题，输出期望值和实际值
## 可能的问题
	- 同一个项目IP固定，端口固定
	- TCP_ACKNOWLEDGEMENT_03 0x8204与0x0200先后顺序
