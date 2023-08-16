package utils

import (
	"fmt"
	"testing"
)

func TestMatchSubdomains(t *testing.T) {
	html := `
HTTP/1.1 200 OK
Date: Fri, 18 Aug 2023 07:04:49 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Server: nginx
Content-Length: 13693

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
<meta name="robots" content="all">
<meta name="referrer" content="always">
<meta name="renderer" content="webkit">
<meta http-equiv="Cache-Control" content="no-transform" />
<meta name="format-detection" content="telephone=no"/>
<meta name="applicable-device" content="pc,mobile"/>
<meta name="apple-mobile-web-app-capable" content="yes"/>
<meta name="apple-mobile-web-app-status-bar-style" content="black"/>
<title>knownsec.com子域名大全 knownsec.com二级域名 knownsec.com域名解析查询</title>
<link type="text/css" rel="stylesheet" href="//cache.ip138.com/site/style/dist/responsive.css?v=202304201300"/>
<link type="text/css" rel="stylesheet" href="//cache.ip138.com/site/style/dist/index.css?v=202304201300"/>
<script>
if(location.hostname.indexOf('.ip138.com')<0){
location.href = 'https://site.ip138.com/';
}else if( window.top != window.self ) {
window.top.location = self.location.href;
}
var _INPUT = 'knownsec.com';
var _TOKEN = '971d3913664fc61cbb4426b864ad037f';
var CONFIG = {
'cacheUrl':'//cache.ip138.com/'
};
</script>
<script defer src="//cache.ip138.com/site/script/dist/method.js?v=202304201300"></script>
</head>
<body>
<div class="wrapper">
<div class="header">
<div class="mod-head">
<ul class="link only-pc">
<li><span class="icon-date"></span></li>
</ul>
<a class="logo" href="http://www.ip138.com/"><img src="//cache.ip138.com/site/image/public/logo.png" width="147" height="50" alt="查询网"></a>
<a class="menu only-mobile" href="javascript:;" rel="nofollow"><span></span><span></span><span></span></a>
</div>
</div>
<div class="container">
<div class="side">
<div class="mod-link">
<div class="bd">
<ul>
<li class="small"><a href="//www.ip138.com/" target="_blank">iP查询</a></li>
<li class="small"><a href="//qq.ip138.com/weather/" target="_blank">天气预报</a></li>
<li><a href="//www.ip138.com/sj/" target="_blank">手机号码归属地查询</a></li>
<li><a href="https://www.liantu.com/" target="_blank">二维码生成器</a></li>
<li><a href="https://caipiao.ip138.com/" target="_blank">彩票开奖查询</a></li>
<li><a href="//bifen.ip138.com/" target="_blank">体育比赛比分</a></li>
<li><a href="https://www.yitaifang.com/" target="_blank">以太坊区块浏览器</a></li>
<li><a href="//www.ip138.com/weizhang.htm" target="_blank">车辆交通违章查询</a></li>
<li class="small"><a href="http://10.ip138.com/" target="_blank">品牌排行榜</a></li>
<li class="small"><a href="//qq.ip138.com/hl.asp" target="_blank">汇率查询</a></li>
<li><a href="//www.ip138.com/jb.htm" target="_blank">国内国际机票查询</a></li>
<li><a href="//qq.ip138.com/train/" target="_blank">国内列车时刻表查询</a></li>
<li class="small"><a href="//qq.ip138.com/tran.htm" target="_blank">在线翻译</a></li>
<li class="small"><a href="//www.ip138.com/ems/" target="_blank">快递查询</a></li>
<li class="small"><a href="//www.ip138.com/post/" target="_blank">区号查询</a></li>
<li class="small"><a href="//www.ip138.com/post/" target="_blank">邮编查询</a></li>
<li><a href="//qq.ip138.com/idsearch/" target="_blank">身份证号码查询验证</a></li>
<li class="small"><a href="//qq.ip138.com/wb/wb.asp" target="_blank">拼音查询</a></li>
<li class="small"><a href="//qq.ip138.com/zt.htm" target="_blank">转贴工具</a></li>
<li><a href="//qq.ip138.com/day/" target="_blank">阴阳转换万年历</a></li>
<li><a href="//www.ip138.com/carlist.htm" target="_blank">全国各地车牌查询表</a></li>
<li><a href="//qq.ip138.com/converter.htm" target="_blank">在线度衡量转换器</a></li>
<li><a href="//www.ip138.com/gb.htm" target="_blank">汉字简体繁体转换</a></li>
</ul>
</div>
</div>
</div>                <div class="content">
<div class="mod-breadcrumb">
<a href="http://www.ip138.com/">首页</a> <span>&gt;</span> <a href="/">服务器iP</a> <span>&gt;</span> <strong>knownsec.com子域名大全</strong>
</div>
<div class="mod-panel">
<div class="banner">
<script type="text/javascript">
(function() {
var s = "_" + Math.random().toString(36).slice(2);
document.write('<div style="" id="' + s + '"></div>');
(window.slotbydup = window.slotbydup || []).push({
id: "u3920846",
container:  s
});
})();
</script>
</div>
<div class="hd">
<h1><a href="/">iP或域名查询</a></h1>
</div>
<div class="bd">
<div class="search">
<input class="input-text" id="input" placeholder="请输入你要查询的iP或域名" type="text" value="knownsec.com">
<input class="input-button" type="button" value="查询" onclick="queryInput();"/>
</div>
<div class="link" id="link">
</div>
<div class="result result3">
<ul class="navs">
<li><a href="/knownsec.com/">iP</a></li>
<li class="active"><a href="javascript:;" rel="nofollow">子域名</a></li>
<li><a href="/knownsec.com/beian.htm">备案</a></li>
<li><a href="https://whois.aizhan.com/knownsec.com/" target="_blank" rel="nofollow">Whois</a></li>
<li>
<a href="https://browser.djkte.cn/mobile/" target="_blank" rel="nofollow">
<img src="https://cache.ip138.com/site/image/da/djkte-cn.png" width="20" height="20"/>
<span>下载器</span>
</a>
</li>
</ul>
<div class="panels">
<div class="panel">
<p>
<a href="/knownsec.com/" target="_blank">knownsec.com</a></p>
<h2 class="name"><strong>knownsec.com</strong>子域名：</h2>
<div id="J_subdomain">
<p><a href="/rs.knownsec.com/" target="_blank">rs.knownsec.com</a></p>
<p><a href="/y2m.knownsec.com/" target="_blank">y2m.knownsec.com</a></p>
<p><a href="/update.knownsec.com/" target="_blank">update.knownsec.com</a></p>
<p><a href="/vpn.knownsec.com/" target="_blank">vpn.knownsec.com</a></p>
<p><a href="/ksvpn.knownsec.com/" target="_blank">ksvpn.knownsec.com</a></p>
<p><a href="/kcon.knownsec.com/" target="_blank">kcon.knownsec.com</a></p>
<p><a href="/blog.knownsec.com/" target="_blank">blog.knownsec.com</a></p>
<p><a href="/mail.knownsec.com/" target="_blank">mail.knownsec.com</a></p>
<p><a href="/huntian.knownsec.com/" target="_blank">huntian.knownsec.com</a></p>
<p><a href="/www.knownsec.com/" target="_blank">www.knownsec.com</a></p>
</div>
<p><a href="https://chaziyu.com/knownsec.com/" target="_blank" rel="nofollow">更多子域名</a></p>
</div>
</div>
</div>
<div class="result result1">
<div class="group">
<ul>
<li class="title"><span>最新域名查询</span></li>
<li><a href="/yy88873.com/" target="_blank">yy88873.com</a></li>
<li><a href="/www.hxaa201.com/" target="_blank">www.knownsec.com</a></li>
<li><a href="/fumanhua3.com/" target="_blank">fumanhua3.com</a></li>
<li><a href="/www.mnzmmz.com/" target="_blank">www.mnzmmz.com</a></li>
<li><a href="/www.zjrobp.com/" target="_blank">www.zjrobp.com</a></li>
<li><a href="/www.7talna.com/" target="_blank">www.7talna.com</a></li>
<li><a href="/yy5060.com/" target="_blank">yy5060.com</a></li>
<li><a href="/www.5bx00t.com/" target="_blank">www.5bx00t.com</a></li>
<li><a href="/uhdsexporn.com/" target="_blank">uhdsexporn.com</a></li>
<li><a href="/a555666.com/" target="_blank">a555666.com</a></li>
<li><a href="/dtkwebblus.com/" target="_blank">dtkwebblus.com</a></li>
<li><a href="/www915.com/" target="_blank">www915.com</a></li>
<li><a href="/www.84.com/" target="_blank">www.84.com</a></li>
<li><a href="/www.7770009.com/" target="_blank">www.7770009.com</a></li>
<li><a href="/www.0wcttz.com/" target="_blank">www.0wcttz.com</a></li>
</ul>
<ul>
<li class="title"><span>最新iP查询</span></li>
<li><a href="/54.152.168.219/" target="_blank">54.152.168.219</a></li>
<li><a href="/34.206.39.153/" target="_blank">34.206.39.153</a></li>
<li><a href="/199.59.148.8/" target="_blank">199.59.148.8</a></li>
<li><a href="/112.25.191.254/" target="_blank">112.25.191.254</a></li>
<li><a href="/31.13.88.26/" target="_blank">31.13.88.26</a></li>
<li><a href="/199.16.156.71/" target="_blank">199.16.156.71</a></li>
<li><a href="/172.67.182.84/" target="_blank">172.67.182.84</a></li>
<li><a href="/107.164.62.53/" target="_blank">107.164.62.53</a></li>
<li><a href="/31.13.94.7/" target="_blank">31.13.94.7</a></li>
<li><a href="/172.67.216.100/" target="_blank">172.67.216.100</a></li>
<li><a href="/223.109.137.253/" target="_blank">223.109.137.253</a></li>
<li><a href="/138.113.34.244/" target="_blank">138.113.34.244</a></li>
<li><a href="/64.32.28.250/" target="_blank">64.32.28.250</a></li>
<li><a href="/61.177.139.150/" target="_blank">61.177.139.150</a></li>
<li><a href="/154.31.2.236/" target="_blank">154.31.2.236</a></li>
</ul>
</div>
<div class="banner link" id="banner1"></div>
<div class="banner">
<script type="text/javascript">
(function() {
var s = "_" + Math.random().toString(36).slice(2);
document.write('<div style="" id="' + s + '"></div>');
(window.slotbydup = window.slotbydup || []).push({
id: "u3920846",
container:  s
});
})();
</script>
</div>
<div class="group">
<ul>
<li class="title"><span>最新备案查询</span></li>
<li><a href="/zz1z.cn/beian.htm" target="_blank">zz1z.cn</a></li>
<li><a href="/zhuojiamei.com/beian.htm" target="_blank">zhuojiamei.com</a></li>
<li><a href="/yjdex.cn/beian.htm" target="_blank">yjdex.cn</a></li>
<li><a href="/shomter.com.cn/beian.htm" target="_blank">shomter.com.cn</a></li>
<li><a href="/re-journal.com/beian.htm" target="_blank">re-journal.com</a></li>
<li><a href="/kunyuecable.com/beian.htm" target="_blank">kunyuecable.com</a></li>
<li><a href="/gpcljskfyy.cn/beian.htm" target="_blank">gpcljskfyy.cn</a></li>
<li><a href="/qhdtdqy.com/beian.htm" target="_blank">qhdtdqy.com</a></li>
<li><a href="/bgi-college.cn/beian.htm" target="_blank">bgi-college.cn</a></li>
<li><a href="/cr173.com/beian.htm" target="_blank">cr173.com</a></li>
<li><a href="/landtz.com/beian.htm" target="_blank">landtz.com</a></li>
<li><a href="/hnskl.net/beian.htm" target="_blank">hnskl.net</a></li>
<li><a href="/ypyly.com/beian.htm" target="_blank">ypyly.com</a></li>
<li><a href="/jchs.cn/beian.htm" target="_blank">jchs.cn</a></li>
<li><a href="/wo.cn/beian.htm" target="_blank">wo.cn</a></li>
</ul>
<ul>
<li class="title"><span>最新子域名查询</span></li>
<li><a href="/yinheshijie.com/domain.htm" target="_blank">yinheshijie.com</a></li>
<li><a href="/lyhrjx.com/domain.htm" target="_blank">lyhrjx.com</a></li>
<li><a href="/lnjgkj.com/domain.htm" target="_blank">lnjgkj.com</a></li>
<li><a href="/gay777.com/domain.htm" target="_blank">gay777.com</a></li>
<li><a href="/anymj.com/domain.htm" target="_blank">anymj.com</a></li>
<li><a href="/antteaneo.com/domain.htm" target="_blank">antteaneo.com</a></li>
<li><a href="/aa572.com/domain.htm" target="_blank">aa572.com</a></li>
<li><a href="/44cao.com/domain.htm" target="_blank">44cao.com</a></li>
<li><a href="/zzz888.com/domain.htm" target="_blank">zzz888.com</a></li>
<li><a href="/zxval.com/domain.htm" target="_blank">zxval.com</a></li>
<li><a href="/x66m.com/domain.htm" target="_blank">x66m.com</a></li>
<li><a href="/my3221.com/domain.htm" target="_blank">my3221.com</a></li>
<li><a href="/luotuohospital.com/domain.htm" target="_blank">luotuohospital.com</a></li>
<li><a href="/dayiinfo.net/domain.htm" target="_blank">dayiinfo.net</a></li>
<li><a href="/aucklandunlimited.com/domain.htm" target="_blank">aucklandunlimited.com</a></li>
</ul>
</div>
<div class="banner link" id="banner2"></div>
<div class="banner">
<script type="text/javascript">
(function() {
var s = "_" + Math.random().toString(36).slice(2);
document.write('<div style="" id="' + s + '"></div>');
(window.slotbydup = window.slotbydup || []).push({
id: "u3920846",
container:  s
});
})();
</script>
</div>
<!-- 多条广告如下脚本只需引入一次 -->
<script type="text/javascript" src="//cpro.baidustatic.com/cpro/ui/cm.js" async="async" defer="defer" ></script>
</div>                        </div>
</div>
</div>
<div class="footer">
<div class="mod-foot">
<div class="logo only-pc"><a href="http://www.ip138.com/"><img src="//cache.ip138.com/site/image/public/logo.png" width="147" height="50" alt="查询网"></a></div>
<div class="info">
<p><span>如果您觉得本站对您的朋友有帮助，别忘了告诉他（她）们哟 ^_^</span></p>
<p>
<span class="contact">联系我们：请<a href="http://www.ip138.com/mail.htm" rel="nofollow" target="_blank">发email</a>或给<a href="http://qq.3533.com:8080/book.asp?siteid=7" rel="nofollow" target="_blank">我们留言</a>谢谢!</span>
</p>
</div>
</div>
<div class="mod-goback">
<a href="#" rel="nofollow">返回顶部</a>
</div>
<div class="mod-mask"></div>
</div>
</div>
</div>
<script defer src="//cache.ip138.com/site/script/dist/common.js?v=202304201300"></script>
<script id="international" defer src="//cache.ip138.com/site/script/dist/international.js?v=202304201300" data-url="//www.dnsdblookup.com/knownsec.com/domain.htm"></script>
<script defer src="//cache.ip138.com/site/script/dist/child.js?v=202304201300"></script>
<script>
(function(){
var bp = document.createElement('script');
var curProtocol = window.location.protocol.split(':')[0];
if (curProtocol === 'https') {
bp.src = 'https://zz.bdstatic.com/linksubmit/push.js';
}
else {
bp.src = 'http://push.zhanzhang.baidu.com/push.js';
}
var s = document.getElementsByTagName("script")[0];
s.parentNode.insertBefore(bp, s);
})();
</script>
<div class="hide">
<script>
var _hmt = _hmt || [];
(function() {
var hm = document.createElement("script");
hm.src = "https://hm.baidu.com/hm.js?9528a85ee34f0781ac55bb6e2c29e7ae";
var s = document.getElementsByTagName("script")[0];
s.parentNode.insertBefore(hm, s);
})();
</script>
</div>
</body>
</html>

`
	subdomains := MatchSubdomains("knownsec.com", html, true)
	fmt.Println(subdomains)
}
