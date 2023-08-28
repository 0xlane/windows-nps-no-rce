# Windows NPS NO RCE

之前 xxx 放出过一个 Windows 域控 RCE 的文档，我也放到仓库里了，说是可以远程实现域控加载任意 DLL 的效果，看似有理有据的所以就看看。

文档中提到的漏洞位置位于 `iassam.dll` 组件，它是 NPS  的 COM 服务组件之一。PDF 中说除了要打开 NPS 服务之外，还要开个什么 IAS 扩展，我查了半天都没搜到这个 IAS 扩展怎么开启，看官网明确写着 NPS 是 IAS 改名后的东西，IAS 并不是 NPS 的扩展，所以 PDF 中的信息后面不用看都有点假，而且看最后截图中的进程树 cmd.exe 父进程是 explorer ???，有点糊弄人了吧。

文档中并没有给他的 exp，只给了个具体漏洞位置：`iassam.dll!RadiusExtensionPoint::Load` ，我用 IDA 大概看了一下调用关系，入口应该是 `IIASExtensionHost:Initialize` ，这是个 COM 接口，参数定义如下：

```cpp
signed int __fastcall ExtensionHost::Initialize(
        __int64 a1,                        // interface self
        enum _RADIUS_EXTENSION_POINT a2,
        unsigned int a3,                   // 0 结尾的 unicode 路径字符串长度
        const unsigned __int16 *a4)        // 0 结尾的 unicode 路径
```

用 `OldViewDotnet` 工具具体看了一下 `IASExtensionHost` 的注册信息：

![x1](https://pict.reinject.top:2083/i/2023/08/28/64ec6f296cd27.png)

所以既然是 COM 接口，那直接按约定传参调用就行了：

```rust
CoInitializeEx(None, COINIT_MULTITHREADED).unwrap();

let iIASExt: IIASExtentionHost = CoCreateInstance(&combase::CLSID_IASExtentionHost, None, CLSCTX_ALL).unwrap();

let dll_path = w!("C:\\Windows\\Temp\\calc.dll");
let mut dll_path_vec = dll_path.as_wide().to_vec();
dll_path_vec.push(0x00);
dll_path_vec.push(0x00);

DebugBreak();

iIASExt.Initialize(
            repAuthorization,
            (dll_path_vec.len() * 2) as u32,
            PCWSTR(dll_path_vec.as_ptr() as *const u16)).unwrap();

println!("OK");

// 清理
CoUninitialize();
```

测试过发现确实可以加载任意 DLL，但是实际加载 dll 的进程是自己编译的这个程序，也就是说 COM 组件被加载到了客户端进程中执行，并没有代理到服务进程执行，服务进程是哪个，我猜是这个，域控上添加了 NPS 才有这个服务：

![x2](https://pict.reinject.top:2083/i/2023/08/28/64ec7c5a097d4.png)

所以我试了改成调用 `CoCreateInstanceEx` 完成远程认证，并将上下文参数设置为 `CLSCTX_REMOTE_SERVER` 强制让接口代理到远程服务端执行而不是在客户端进程，但是很遗憾发生了报错，远端拒绝访问，管理员也不行：

![x3](https://pict.reinject.top:2083/i/2023/08/28/64ec7c86af46f.png)

经过这么一看，文档中的漏洞并不存在，只能算是一种另类的 DLL 加载方式（不直接调用 `LoadLibrary`）。

总结：一本正经地胡说八道，当然如果能解决远程拒绝访问的问题那估计就可以远程 R 了。

测试代码也放到仓库了，想自己测试一下的自取。
