import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import os
import sys

class SM4ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SM4加密TCP聊天工具")
        self.root.geometry("800x600")
        self.root.resizable(False, False)

        # 进程相关变量
        self.chat_process = None
        self.read_thread = None
        self.is_running = False

        # 1. 模式选择区域
        self.mode_frame = ttk.LabelFrame(root, text="运行模式")
        self.mode_frame.pack(fill="x", padx=10, pady=5)

        self.mode_var = tk.StringVar(value="server")
        self.server_radio = ttk.Radiobutton(
            self.mode_frame, text="服务端（Server）", 
            variable=self.mode_var, value="server",
            command=self.toggle_ip_input
        )
        self.server_radio.grid(row=0, column=0, padx=10, pady=5)

        self.client_radio = ttk.Radiobutton(
            self.mode_frame, text="客户端（Client）", 
            variable=self.mode_var, value="client",
            command=self.toggle_ip_input
        )
        self.client_radio.grid(row=0, column=1, padx=10, pady=5)

        self.ip_label = ttk.Label(self.mode_frame, text="服务端IP：")
        self.ip_label.grid(row=0, column=2, padx=5, pady=5)
        self.ip_entry = ttk.Entry(self.mode_frame, width=15)
        self.ip_entry.insert(0, "127.0.0.1")  # 默认本地IP
        self.ip_entry.grid(row=0, column=3, padx=5, pady=5)
        self.ip_label.config(state="disabled")
        self.ip_entry.config(state="disabled")

        # 2. 控制按钮区域
        self.ctrl_frame = ttk.Frame(root)
        self.ctrl_frame.pack(fill="x", padx=10, pady=5)

        self.start_btn = ttk.Button(
            self.ctrl_frame, text="启动", 
            command=self.start_chat, width=10
        )
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(
            self.ctrl_frame, text="停止", 
            command=self.stop_chat, width=10,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5)

        # 3. 日志显示区域
        self.log_frame = ttk.LabelFrame(root, text="运行日志/聊天内容")
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(
            self.log_frame, wrap=tk.WORD, state="disabled"
        )
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

        # 4. 消息输入区域
        self.input_frame = ttk.Frame(root)
        self.input_frame.pack(fill="x", padx=10, pady=5)

        self.msg_entry = ttk.Entry(self.input_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.msg_entry.bind("<Return>", self.send_message)  # 回车发送

        self.send_btn = ttk.Button(
            self.input_frame, text="发送", 
            command=self.send_message, width=10
        )
        self.send_btn.pack(side="right", padx=5)

    def toggle_ip_input(self):
        """切换IP输入框的启用/禁用状态"""
        if self.mode_var.get() == "client":
            self.ip_label.config(state="normal")
            self.ip_entry.config(state="normal")
        else:
            self.ip_label.config(state="disabled")
            self.ip_entry.config(state="disabled")

    def append_log(self, text):
        """向日志框追加内容（线程安全）"""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)  # 滚动到末尾
        self.log_text.config(state="disabled")

    def read_process_output(self):
        """读取子进程输出并显示（线程执行）"""
        while self.is_running and self.chat_process:
            try:
                # 实时读取输出（按行）
                line = self.chat_process.stdout.readline()
                if not line:
                    break
                self.append_log(line.strip())
            except Exception as e:
                self.append_log(f"[读取输出异常] {str(e)}")
                break

        # 进程结束后清理
        self.is_running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.append_log("[进程结束] 聊天程序已退出")

    def start_chat(self):
        """启动聊天程序（服务端/客户端）"""
        # 检查可执行文件是否存在
        if self.mode_var.get() == "server":
            exe_path = "./server"
            args = []
        else:
            exe_path = "./client"
            ip = self.ip_entry.get().strip()
            if not ip:
                messagebox.showerror("错误", "请输入服务端IP地址！")
                return
            args = [ip]

        if not os.path.exists(exe_path):
            messagebox.showerror("错误", f"未找到可执行文件：{exe_path}\n请先编译C代码！")
            return

        # 停止已有进程
        if self.is_running:
            self.stop_chat()

        try:
            # 启动子进程（重定向标准输入/输出/错误）
            self.chat_process = subprocess.Popen(
                [exe_path] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # 合并stderr到stdout
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self.is_running = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.append_log(f"[启动成功] 模式：{self.mode_var.get()}")

            # 启动线程读取输出
            self.read_thread = threading.Thread(target=self.read_process_output, daemon=True)
            self.read_thread.start()

        except Exception as e:
            messagebox.showerror("错误", f"启动失败：{str(e)}")
            self.is_running = False

    def stop_chat(self):
        """停止聊天程序"""
        if self.is_running and self.chat_process:
            try:
                # 发送退出指令并终止进程
                self.chat_process.stdin.write("exit\n")
                self.chat_process.stdin.flush()
                self.chat_process.terminate()
                self.chat_process.wait(timeout=3)
            except Exception as e:
                self.append_log(f"[停止异常] {str(e)}")
            finally:
                self.is_running = False
                self.start_btn.config(state="normal")
                self.stop_btn.config(state="disabled")
                self.append_log("[已停止] 聊天程序已终止")

    def send_message(self, event=None):
        """发送消息到子进程"""
        if not self.is_running or not self.chat_process:
            messagebox.showwarning("警告", "请先启动聊天程序！")
            return

        msg = self.msg_entry.get().strip()
        if not msg:
            return

        try:
            # 向子进程输入写入消息（加换行符）
            self.chat_process.stdin.write(msg + "\n")
            self.chat_process.stdin.flush()
            self.msg_entry.delete(0, tk.END)  # 清空输入框
        except Exception as e:
            self.append_log(f"[发送失败] {str(e)}")
            self.stop_chat()

    def on_closing(self):
        """窗口关闭时清理资源"""
        if self.is_running:
            self.stop_chat()
        self.root.destroy()

if __name__ == "__main__":
    # 检查Python版本（确保兼容）
    if sys.version_info < (3, 6):
        messagebox.showerror("错误", "请使用Python 3.6及以上版本！")
        sys.exit(1)

    root = tk.Tk()
    app = SM4ChatGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
