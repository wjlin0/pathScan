#
pathScan ��һ����Go��д��·��ɨ�蹤�ߣ������������ٿɿ���ɨ��URL��ַ������һ���ǳ��򵥵Ĺ��ߡ�

## ����

```console
pathScan -u http://www.google.com/ -ps /docs

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.1
/_/

                        wjlin0.com

���á���ҪΪ�Լ�����Ϊ����
�����߲��е��κ����Σ�Ҳ�����κ����û��𻵸���.
[INF] ״̬��200 http://www.google.com:80/docs ���±���: Sign in - Google Accounts ҳ�泤��:144418
```

- ���ٷ���·��
- ��Զ�̼���Ŀ���Զ�̼����ֵ�
- �ḻ�������ֵ�,�Զ������ֵ�
- �ɻָ��ϴ�ɨ�����
- ֧��ʹ��HTTP/SOCKS����
- ���UserAgent

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
  -pb, -progressbar   ���ý�����

����:
  -rs, -retries int        ����3�� (default 3)
  -p, -proxy string        ����
  -pa, -proxy-auth string  ������֤����ð�ŷָusername:password��
  -st, -scan-target        ֻ����Ŀ����ɨ��

����:
  -rl, -rate-limit int  �߳� (default 300)
  -rh, -rate-http int   ����ÿ�������http������ (default 100)
```
## ��װ

����׼�����е�[�������ļ�](https://github.com/wjlin0/pathScan/releases/latest)��ʹ�� GO ��װ
### GO
```shell
go install -v github.com/wjlin0/pathScan@latest
```
### Docker
������ - ��������

## Զ�̼���
```console
pathScan -u http://www.google.com/ -pr https://raw.githubusercontent.com/wjlin0/pathScan/main/dict/api-user.txt

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.1
/_/

                        wjlin0.com

���á���ҪΪ�Լ�����Ϊ����
�����߲��е��κ����Σ�Ҳ�����κ����û��𻵸���.
[INF] ��Զ�̼����ֵ� ���...
[INF] ״̬��200 http://www.google.com:80/apis ���±���: Google Code ҳ�泤��:5325
[INF] ״̬��200 http://www.google.com:80/apis/ ���±���: Google Code ҳ�泤��:5325
```
## ��ͨ���м���Ŀ��
������ - ��������

## ��ϸģʽ
```console
pathScan -u https://google.com -vb

[DBG] Զ���ֵ����سɹ�-> /root/.config/pathScan/dict

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.1
/_/

                        wjlin0.com

���á���ҪΪ�Լ�����Ϊ����
�����߲��е��κ����Σ�Ҳ�����κ����û��𻵸���.
[DBG] ���� https://google.com ���
[INF] ���Ŀ������ -> 1
[INF] �������� -> 18408
[VER] ״̬�� 301 https://google.com/developer ���±���  ҳ�泤�� 229
[VER] ״̬�� 301 https://google.com/profiles/testing/testing.info ���±���  ҳ�泤�� 249
[VER] ״̬�� 301 https://google.com/technology ���±���  ҳ�泤�� 230
[VER] ״̬�� 301 https://google.com/survey ���±���  ҳ�泤�� 226
[VER] ״̬�� 404 https://google.com/js/tinymce/ ���±��� Error 404 (Not Found)!!1 ҳ�泤�� 1572
```
## ֻ���200ģʽ
```console
pathScan -u https://google.com -sl
https://google.com
https://google.com/partners
```
## �ָ�ɨ��
- ע��ʹ�� �ظ�ɨ�� ����������Ϊ��һ����������
```console
pathScan -resume Hc7wUXRoH2G1RjrNgjB2OMzXlXo1Hg.cfg

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.1
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

## ����������
```console
pathScan -u https://google.com -st

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.1
/_/

                        wjlin0.com

���á���ҪΪ�Լ�����Ϊ����
�����߲��е��κ����Σ�Ҳ�����κ����û��𻵸���.
[INF] ���� https://google.com ���
```
## ��л

- [projectdiscovery.io](https://projectdiscovery.io/#/)
