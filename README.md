#
pathScan ��һ����Go��д��·��ɨ�蹤�ߣ������������ٿɿ���ɨ��URL��ַ������һ���ǳ��򵥵Ĺ��ߡ�

## ����

```console
pathScan -u http://www.google.com/ -ps /docs

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.0
/_/

                        wjlin0.com

���á���ҪΪ�Լ�����Ϊ����
�����߲��е��κ����Σ�Ҳ�����κ����û��𻵸���.
[INF] ״̬��200 http://www.google.com:80/docs ���±���: Sign in - Google Accounts ҳ�泤��:144418
```

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
  ./pathScan [flags]

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

����׼�����е�[�������ļ�](https://github.com/wjlin0/pathScan/releases/latest)��ʹ�� GO ��װ
### GO
```shell
go install -v github.com/wjlin0/pathScan
```
## Զ�̼���
```console
pathScan -u http://www.google.com/ -pr https://raw.githubusercontent.com/wjlin0/pathScan/main/dict/api-user.txt

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.0
/_/

                        wjlin0.com

���á���ҪΪ�Լ�����Ϊ����
�����߲��е��κ����Σ�Ҳ�����κ����û��𻵸���.
[INF] ��Զ�̼����ֵ� ���...
[INF] ״̬��200 http://www.google.com:80/apis ���±���: Google Code ҳ�泤��:5325
[INF] ״̬��200 http://www.google.com:80/apis/ ���±���: Google Code ҳ�泤��:5325```
```

## ��ϸģʽ
```console
pathScan -u http://www.google.com/ -ps /docs,/api/user -vb

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.0
/_/

                        wjlin0.com

���á���ҪΪ�Լ�����Ϊ����
�����߲��е��κ����Σ�Ҳ�����κ����û��𻵸���.
[WRN] ״̬��404 http://www.google.com:80/api/user ���±���: Error 404 (Not Found)!!1 ҳ�泤��:1569
[INF] ״̬��200 http://www.google.com:80/docs ���±���: Sign in - Google Accounts ҳ�泤��:144550
```
## �ָ�ɨ��
- ע��ʹ�� �ظ�ɨ�� ����������Ϊ��һ����������
```console
pathScan -resume Hc7wUXRoH2G1RjrNgjB2OMzXlXo1Hg.cfg

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.0
/_/

                        wjlin0.com

���á���ҪΪ�Լ�����Ϊ����
�����߲��е��κ����Σ�Ҳ�����κ����û��𻵸���.
[WRN] ״̬��404 http://www.google.com:80/lyfhtxy ���±���: Error 404 (Not Found)!!1 ҳ�泤��:1568
[WRN] ״̬��404 http://www.google.com:80/en/netdu ���±���: Error 404 (Not Found)!!1 ҳ�泤��:1569
[WRN] ״̬��404 http://www.google.com:80/a_zbzn ���±���: Error 404 (Not Found)!!1 ҳ�泤��:1567
```
## �����ļ�
pathScan ֧��Ĭ�������ļ�λ��$HOME/.config/pathScan/config.yaml�����������������ļ��ж����κα�־������Ĭ��ֵ�԰�������ɨ�衣

## �����ų�
pathScan �Զ�̽���������������ų�����ʧ�ܵ�URL
## ��л

- [projectdiscovery.io](https://projectdiscovery.io/#/)
