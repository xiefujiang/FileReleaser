import os
import sys
import ctypes
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import psutil

class FileUnlockerApp:
    """
    主应用程序类：负责调度文件解锁引擎。
    实现 Tkinter 现代化图形界面，并封装底层系统句柄扫描矩阵。
    """
    def __init__(self, root):
        self.root = root
        self.root.title("文件占用释放工具 v1.0")
        self.root.geometry("800x560")
        self.root.minsize(700, 450)
        
        # UI配色方案
        self.COLOR_BG = "#F3F4F6"            # 科技浅灰背景
        self.COLOR_CARD = "#FFFFFF"          # 纯白卡片底色
        self.COLOR_PRIMARY = "#1F4E79"       # 微软深邃蓝（主色调）
        self.COLOR_PRIMARY_HOVER = "#2C669E" # 主色调鼠标悬停色
        self.COLOR_DANGER = "#C0392B"        # 警告深红（破坏性操作）
        self.COLOR_DANGER_HOVER = "#E74C3C"  # 警告深红鼠标悬停色
        self.COLOR_TEXT_MAIN = "#2C3E50"     # 深木炭黑（主文字颜色）
        self.COLOR_TEXT_MUTED = "#7F8C8D"    # 石板灰（次要/暗淡文字）
        self.COLOR_BORDER = "#E5E7EB"        # 极浅网格线边框色
        
        self.root.configure(bg=self.COLOR_BG)
        
        # --- 内部数据流存储矩阵 ---
        self.found_processes = []  # 存储匹配到的进程字典数组 (包含 pid, name, exe)
        self.check_vars = []       # 存储复选框状态变量的数组 (tk.BooleanVar)
        
        self.initialize_ui_components()
        self.verify_privilege_escalation()
        try:
            if hasattr(sys, '_MEIPASS'):
                # 如果是打包后的环境，从 PyInstaller 的临时释放目录读取图标
                icon_path = os.path.join(sys._MEIPASS, "avatar.ico")
            else:
                # 如果是开发环境，直接读取同级目录
                icon_path = "avatar.ico"
                
            self.root.iconbitmap(icon_path)
        except Exception:
            pass


    def verify_privilege_escalation(self):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except KeyError:
            is_admin = False
            
        if not is_admin:
            messagebox.showwarning(
                "权限级别通知", 
                "当前程序以非管理员模式运行，某些应用可能无法被扫描或终止。"
            )

    def initialize_ui_components(self):
        # =========================================================================
        # 【核心修复点：重构 Pack 声明顺序】
        # 先声明并挂载底部操作卡片（Side="bottom"），从而赋予它绝对的“空间优先分配权”
        # =========================================================================
        footer_frame = tk.Frame(self.root, bg=self.COLOR_BG, pady=10)
        footer_frame.pack(side="bottom", fill="x", padx=24) # 显式指定贴紧底部，永不被裁剪
        
        self.lbl_status = tk.Label(footer_frame, text="就绪。等待输入目标路径并初始化内核扫描......", font=("Microsoft YaHei", 9), bg=self.COLOR_BG, fg=self.COLOR_TEXT_MUTED)
        self.lbl_status.pack(side="left")
        
        self.btn_kill = self.create_flat_button(footer_frame, "强制强杀选中进程 (Kill)", self.COLOR_DANGER, "white", self.kill_selected_processes, self.COLOR_DANGER_HOVER)
        self.btn_kill.configure(state="disabled", font=("Microsoft YaHei", 9, "bold"))
        self.btn_kill.pack(side="right")

        # 模块 1: 顶部 - 目标路径选择卡片
        card_path = tk.Frame(self.root, bg=self.COLOR_CARD, bd=1, relief="flat", padx=16, pady=16)
        card_path.pack(side="top", fill="x", padx=20, pady=(20, 10))
        card_path.configure(highlightbackground=self.COLOR_BORDER, highlightthickness=1)
        
        lbl_title = tk.Label(card_path, text="被占用文件的的目标路径 (文件或文件夹)", font=("Microsoft YaHei", 10, "bold"), bg=self.COLOR_CARD, fg=self.COLOR_PRIMARY)
        lbl_title.pack(anchor="w", pady=(0, 6))
        
        action_frame = tk.Frame(card_path, bg=self.COLOR_CARD)
        action_frame.pack(fill="x")
        
        self.entry_path = tk.Entry(action_frame, font=("Microsoft YaHei", 10), bg="#F9FAFB", fg=self.COLOR_TEXT_MAIN,
                                   relief="flat", highlightthickness=1, highlightbackground=self.COLOR_BORDER,
                                   insertbackground=self.COLOR_TEXT_MAIN)
        self.entry_path.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 10))
        
        self.create_flat_button(action_frame, "选择文件...", "#E5E7EB", self.COLOR_TEXT_MAIN, self.browse_file, "#D1D5DB").pack(side="left", padx=2)
        self.create_flat_button(action_frame, "选择文件夹...", "#E5E7EB", self.COLOR_TEXT_MAIN, self.browse_directory, "#D1D5DB").pack(side="left", padx=2)
        
        btn_scan = self.create_flat_button(action_frame, "开始扫描", self.COLOR_PRIMARY, "white", self.scan_occupancy, self.COLOR_PRIMARY_HOVER)
        btn_scan.pack(side="left", padx=(8, 0))

        # 模块 2: 中部 - 数据网格 / 进程列表卡片
        card_list = tk.Frame(self.root, bg=self.COLOR_CARD, bd=1, relief="flat", padx=16, pady=12)
        card_list.pack(side="top", fill="both", expand=True, padx=20, pady=10) # 允许在剩余空间中自由缩放
        card_list.configure(highlightbackground=self.COLOR_BORDER, highlightthickness=1)
        
        toolbar = tk.Frame(card_list, bg=self.COLOR_CARD)
        toolbar.pack(fill="x", pady=(0, 8))
        
        lbl_list_title = tk.Label(toolbar, text="活跃进程列表", font=("Microsoft YaHei", 10, "bold"), bg=self.COLOR_CARD, fg=self.COLOR_TEXT_MAIN)
        lbl_list_title.pack(side="left")
        
        btn_all = tk.Button(toolbar, text="全选", font=("Microsoft YaHei", 9), bg=self.COLOR_CARD, fg="#3498DB", relief="flat", activebackground=self.COLOR_CARD, command=self.select_all)
        btn_all.pack(side="right", padx=6)
        btn_none = tk.Button(toolbar, text="全不选", font=("Microsoft YaHei", 9), bg=self.COLOR_CARD, fg=self.COLOR_TEXT_MUTED, relief="flat", activebackground=self.COLOR_CARD, command=self.select_none)
        btn_none.pack(side="right", padx=6)

        self.canvas = tk.Canvas(card_list, bg=self.COLOR_CARD, highlightthickness=0)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Vertical.TScrollbar", gripcount=0, background="#E5E7EB", darkcolor="#E5E7EB", lightcolor="#E5E7EB", troughcolor=self.COLOR_CARD, bordercolor=self.COLOR_CARD, arrowcolor=self.COLOR_TEXT_MUTED)
        
        scrollbar = ttk.Scrollbar(card_list, orient="vertical", command=self.canvas.yview, style="Vertical.TScrollbar")
        
        self.scroll_window = tk.Frame(self.canvas, bg=self.COLOR_CARD)
        
        self.scroll_window.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.canvas_frame, width=e.width))
        
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.scroll_window, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 保持监听窗口尺寸变化，动态调节滚动响应
        self.root.bind("<Configure>", lambda e: self.update_scroll_lock())

    def create_flat_button(self, parent, text, bg, fg, command, hover_bg):
        btn = tk.Button(parent, text=text, font=("Microsoft YaHei", 9), bg=bg, fg=fg, relief="flat", 
                        activebackground=hover_bg, activeforeground=fg, padx=14, pady=4, cursor="hand2", command=command)
        btn.bind("<Enter>", lambda e: btn.configure(bg=hover_bg) if btn['state'] != 'disabled' else None)
        btn.bind("<Leave>", lambda e: btn.configure(bg=bg) if btn['state'] != 'disabled' else None)
        return btn

    def browse_file(self):
        path = filedialog.askopenfilename(title="选择被锁定的目标文件")
        if path:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, os.path.normpath(path))

    def browse_directory(self):
        path = filedialog.askdirectory(title="选择被锁定的目标文件夹")
        if path:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, os.path.normpath(path))

    def update_scroll_lock(self):
        self.root.update_idletasks()
        content_height = self.scroll_window.winfo_reqheight()
        view_height = self.canvas.winfo_height()

        if content_height <= view_height:
            self.canvas.unbind_all("<MouseWheel>") 
            self.canvas.yview_moveto(0)            
        else:
            self.canvas.bind_all("<MouseWheel>", lambda event: self.canvas.yview_scroll(int(-1*(event.delta/120)), "units"))

    def create_selectable_text(self, parent, text, font, bg, fg, width=None):
        var = tk.StringVar(value=text)
        entry = tk.Entry(
            parent, textvariable=var, font=font, bg=bg, fg=fg,
            relief="flat", bd=0, highlightthickness=0, 
            readonlybackground=bg, selectbackground="#3498DB", selectforeground="white"
        )
        if width:
            entry.configure(width=width)
        entry.configure(state="readonly") 
        return entry

    def scan_occupancy(self):
        target_path = self.entry_path.get().strip('" ').strip()
        if not target_path:
            self.lbl_status.configure(text="就绪。", fg=self.COLOR_TEXT_MUTED)
            return
            
        if not os.path.exists(target_path):
            messagebox.showerror("IO错误", "指定的跟踪路径无法被操作系统环境解析，请检查路径是否正确。")
            return

        target_path_lower = os.path.abspath(target_path).lower()
        
        for widget in self.scroll_window.winfo_children():
            widget.destroy()
        self.found_processes.clear()
        self.check_vars.clear()
        self.btn_kill.configure(state="disabled", bg=self.COLOR_DANGER)
        
        self.lbl_status.configure(text="正在扫描系统进程，请稍候...", fg=self.COLOR_PRIMARY)
        self.root.update()

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                open_files = proc.open_files()
                for f in open_files:
                    if f.path.lower().startswith(target_path_lower):
                        if proc.info['pid'] not in [p['pid'] for p in self.found_processes]:
                            self.found_processes.append(proc.info)
                        break 
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if not self.found_processes:
            self.lbl_status.configure(text="扫描完毕：未发现与该文件(夹)有关的活跃进程。", fg="#27AE60")
            no_res_lbl = tk.Label(self.scroll_window, text="没有进程占用此路径。", font=("Microsoft YaHei", 10, "italic"), bg=self.COLOR_CARD, fg=self.COLOR_TEXT_MUTED, pady=30)
            no_res_lbl.pack(fill="x", anchor="center")
        else:
            self.lbl_status.configure(text=f"扫描完毕：已成功锁定 {len(self.found_processes)} 个正在阻占文件的进程目标。", fg=self.COLOR_DANGER)
            self.btn_kill.configure(state="normal")
            
            header_frame = tk.Frame(self.scroll_window, bg="#F8FAFC", pady=6)
            header_frame.pack(fill="x", expand=True)
            tk.Label(header_frame, text=" 勾选", font=("Microsoft YaHei", 9, "bold"), bg="#F8FAFC", fg=self.COLOR_TEXT_MAIN, width=6, anchor="w").pack(side="left", padx=6)
            tk.Label(header_frame, text="PID", font=("Microsoft YaHei", 9, "bold"), bg="#F8FAFC", fg=self.COLOR_TEXT_MAIN, width=10, anchor="w").pack(side="left")
            tk.Label(header_frame, text="进程程序特征名称", font=("Microsoft YaHei", 9, "bold"), bg="#F8FAFC", fg=self.COLOR_TEXT_MAIN, width=22, anchor="w").pack(side="left")
            
            lbl_header_exe = tk.Label(header_frame, text="可执行文件路径 (.exe path)", font=("Microsoft YaHei", 9, "bold"), bg="#F8FAFC", fg=self.COLOR_TEXT_MAIN, anchor="w")
            lbl_header_exe.pack(side="left", fill="x", expand=True)

            for idx, proc_info in enumerate(self.found_processes):
                row_bg = self.COLOR_CARD if idx % 2 == 0 else "#FAFAFA"
                row_frame = tk.Frame(self.scroll_window, bg=row_bg, pady=8)
                row_frame.pack(fill="x", expand=True)
                
                var = tk.BooleanVar(value=True)
                self.check_vars.append(var)
                chk = tk.Checkbutton(row_frame, variable=var, bg=row_bg, activebackground=row_bg, bd=0)
                chk.pack(side="left", padx=(14, 5))
                
                lbl_pid = self.create_selectable_text(row_frame, str(proc_info['pid']), ("Consolas", 9), row_bg, self.COLOR_TEXT_MAIN, width=10)
                lbl_pid.pack(side="left")
                
                lbl_name = self.create_selectable_text(row_frame, proc_info['name'], ("Microsoft YaHei", 9, "bold"), row_bg, self.COLOR_PRIMARY, width=22)
                lbl_name.pack(side="left")
                
                exe_path = proc_info['exe'] if proc_info['exe'] else "内核映射空间 / 系统受保护核心模块"
                
                lbl_exe = self.create_selectable_text(row_frame, exe_path, ("Microsoft YaHei", 9), row_bg, self.COLOR_TEXT_MUTED, width=100)
                lbl_exe.pack(side="left", fill="x", expand=True)
                
        self.root.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.update_scroll_lock()

    def select_all(self):
        for var in self.check_vars:
            var.set(True)

    def select_none(self):
        for var in self.check_vars:
            var.set(False)

    def kill_selected_processes(self):
        selected_pids = []
        selected_names = []
        
        for idx, var in enumerate(self.check_vars):
            if var.get():
                selected_pids.append(self.found_processes[idx]['pid'])
                selected_names.append(self.found_processes[idx]['name'])
                
        if not selected_pids:
            messagebox.showwarning("运行失败", "没有选择任何活跃进程目标。")
            return
            
        confirm = messagebox.askyesno(
            "进程终止确认", 
            f"您确定要向选中的 {len(selected_pids)} 个进程强制发送关闭信号吗？\n\n" + 
            ", ".join(selected_names[:5]) + ("..." if len(selected_names) > 5 else "") + 
            "\n\n警告: 强制终止含有未保存数据的软件可能会导致数据丢失!"
        )
        
        if not confirm:
            return
            
        success_count = 0
        fail_count = 0
        
        for pid in selected_pids:
            try:
                if psutil.pid_exists(pid):
                    proc = psutil.Process(pid)
                    proc.kill()  
                    success_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                fail_count += 1
                
        if fail_count == 0:
            messagebox.showinfo("任务执行完毕", f"已成功终止选中的 {success_count} 个阻占目标。\n系统将再次扫描以检查是否释放占用，请稍候...")
        else:
            messagebox.showinfo("任务未执行成功", f"强制清理完成，但部分目标受特权保护：\n成功切断: {success_count}个\n失败归档: {fail_count}个 (由于OS内核安全层级拦截)")
            
        self.lbl_status.configure(text="正在重刷文件描述符并重组句柄状态机...", fg="orange")
        self.root.after(500, self.scan_occupancy)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileUnlockerApp(root)
    root.mainloop()