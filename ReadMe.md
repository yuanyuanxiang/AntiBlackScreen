# AntiBlackScreen

![demo](./images/demo.gif)

有一些软件会采用反截图限制，使得我们无法截图，远程控制显示为黑屏。为此需要一种反黑屏技术来爆破。

该程序实现了一种反黑屏技术：`DLL`实现了对SetWindowDisplayAffinity和GetWindowDisplayAffinity进行挂钩，
注入器将`DLL`以shell code形式注入采取了反截屏的进程，并取消其禁止截屏的限制。

注意：64位进程只能由64位注入器进行反截图，调试版本进程只能注入调试版本的shell code。否则，程序可能崩溃。

Here is the technical translation into English:

Some software employs anti-screenshot restrictions, preventing us from capturing screenshots and causing remote control sessions to display as black screens. To address this, an anti-black screen technique is required to bypass these limitations.

This program implements an anti-black screen solution: The DLL hooks SetWindowDisplayAffinity and GetWindowDisplayAffinity. The injector loads the DLL as shellcode into the anti-screenshot-protected process, effectively lifting its screenshot-blocking restrictions.

Note:

A 64-bit process can only be targeted by a 64-bit injector for anti-screenshot bypass.

Debug-mode processes can only accept debug-version shellcode injections.
Failure to adhere to these conditions may cause the program to crash.
