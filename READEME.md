#
pathScan ��һ����Go��д��·��ɨ�蹤�ߣ������������ٿɿ���ɨ��URL��ַ������һ���ǳ��򵥵Ĺ��ߡ�

## ����

![img.png](image/img.png)

- ���ٷ���·��
- ��Զ�̼���Ŀ���Զ�̼����ֵ�
- �ḻ�������ֵ�
- �ɻָ��ϴ�ɨ�����
- ֧��ʹ��HTTP/SOCKS����
- ����ʶ��Ŀ���ַ (example.com ��http://example.com/ �Լ�http://example.com �����ᱨ��)
## �÷�
```shell
pathScan -h
```
```yaml
Usage:
  ./pathScan_linux [flags]

Flags:
����:
   -u, -url string[]        Ŀ��(�Զ��ŷָ�)
   -uf, -url-file string[]  ���ļ���,��ȡĿ��
   -ur, -url-remote string  ��Զ�̼���Ŀ��
   -resume string           ʹ��resume.cfg�ָ�ɨ��

ɨ���ֵ�:
   -ps, -path string[]       ·��(�Զ��ŷָ�)
   -pf, -path-file string[]  ���ļ���,��ȡ·��
   -pr, -path-remote string  ��Զ�̼����ֵ�

���:
   -o, -output string  ����ļ�·�����ɺ��ԣ�
   -nc, -no-color      ����ɫ���
   -vb, -verbose       ��ϸ���ģʽ
   -sl, -silent        ֻ���״̬��Ϊ200

����:
   -rs, -retries int        ����3�� (default 3)
   -p, -proxy string        ����
   -pa, -proxy-auth string  ������֤����ð�ŷָusername:password��

����:
   -rl, -rate-limit int  �߳�(Ĭ��150) (default 150)
```
## ��װ

����׼�����еĶ������ļ���ʹ�� GO ��װ
### GO
```shell
go install -v 
```