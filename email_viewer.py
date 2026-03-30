#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
email_viewer.py - Интерактивный просмотр писем с анализом репутации
Поддерживает:
- Поиск по email, домену, IP
- Отображение SPF/DKIM/DMARC статусов
- Отображение репутации из VirusTotal
- Просмотр вложений с хешами и VT результатами
- Список засвеченных индикаторов
- Пагинация и фильтрация
- Просмотр ссылок на облачные хранилища
- Расширенная статистика
"""

import sqlite3
import sys
import os
import json
from datetime import datetime
from pathlib import Path

class Colors:
    """Цвета для терминала"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    DIM = '\033[2m'

class EmailViewer:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        
    def connect(self):
        """Подключение к базе данных"""
        if not os.path.exists(self.db_path):
            print(f"{Colors.RED}❌ Ошибка: База данных {self.db_path} не найдена!{Colors.END}")
            return False
        
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        return True
    
    def close(self):
        """Закрытие соединения"""
        if self.conn:
            self.conn.close()
    
    def escape_url(self, url):
        """Экранирование URL для безопасного отображения"""
        return url.replace('.', '[.]').replace(':', '[:]').replace('/', '[/]')
    
    def get_reputation_icon(self, status):
        """Получение иконки для статуса репутации"""
        icons = {
            'good': f"{Colors.GREEN}✓{Colors.END}",
            'warning': f"{Colors.YELLOW}⚠{Colors.END}",
            'bad': f"{Colors.RED}✗{Colors.END}",
            'malicious': f"{Colors.RED}💀{Colors.END}",
            'suspicious': f"{Colors.YELLOW}?{Colors.END}",
            'clean': f"{Colors.GREEN}✓{Colors.END}",
            'unknown': f"{Colors.DIM}?{Colors.END}",
            'poor': f"{Colors.RED}✗{Colors.END}",
            'error': f"{Colors.RED}⚠{Colors.END}"
        }
        return icons.get(status, f"{Colors.DIM}?{Colors.END}")
    
    def get_auth_status_color(self, status):
        """Цвет для статуса аутентификации"""
        colors = {
            'valid': Colors.GREEN,
            'invalid': Colors.RED,
            'not_found': Colors.YELLOW,
            'error': Colors.RED,
            'unknown': Colors.DIM
        }
        return colors.get(status, Colors.DIM)
    
    def search_emails(self, term, search_type="any", filter_type="all"):
        """Поиск писем пользователя с фильтрацией"""
        
        if search_type == "email":
            query = """
                SELECT file_number, subject, sender_domain, sender_email, sender_ip, 
                       has_attachment, message_date, body_text, extracted_urls
                FROM emails 
                WHERE sender_email LIKE ?
            """
            params = (f"%{term}%",)
        elif search_type == "domain":
            query = """
                SELECT file_number, subject, sender_domain, sender_email, sender_ip, 
                       has_attachment, message_date, body_text, extracted_urls
                FROM emails 
                WHERE sender_domain LIKE ?
            """
            params = (f"%{term}%",)
        elif search_type == "username":
            query = """
                SELECT file_number, subject, sender_domain, sender_email, sender_ip, 
                       has_attachment, message_date, body_text, extracted_urls
                FROM emails 
                WHERE sender_email LIKE ?
            """
            params = (f"%{term}%@%",)
        elif search_type == "ip":
            query = """
                SELECT file_number, subject, sender_domain, sender_email, sender_ip, 
                       has_attachment, message_date, body_text, extracted_urls
                FROM emails 
                WHERE sender_ip LIKE ?
            """
            params = (f"%{term}%",)
        else:
            query = """
                SELECT file_number, subject, sender_domain, sender_email, sender_ip, 
                       has_attachment, message_date, body_text, extracted_urls
                FROM emails 
                WHERE sender_email LIKE ? 
                   OR sender_domain LIKE ?
                   OR sender_ip LIKE ?
            """
            params = (f"%{term}%", f"%{term}%", f"%{term}%")
        
        if filter_type == "attachments":
            query += " AND has_attachment = 1"
        elif filter_type == "urls":
            query += " AND extracted_urls IS NOT NULL AND extracted_urls != '' AND extracted_urls != '[]'"
        
        query += " ORDER BY file_number"
        
        self.cursor.execute(query, params)
        return self.cursor.fetchall()
    
    def get_email_attachments(self, file_number):
        """Получение вложений для письма"""
        self.cursor.execute("""
            SELECT filename, content_type, size, md5, sha1, sha256,
                   vt_malicious, vt_suspicious, vt_score, reputation_status
            FROM attachments 
            WHERE file_number = ?
        """, (file_number,))
        return self.cursor.fetchall()
    
    def get_domain_reputation(self, domain):
        """Получение репутации домена"""
        if not domain:
            return None
        self.cursor.execute("""
            SELECT spf_status, dkim_status, dmarc_status, auth_score,
                   vt_malicious, vt_suspicious, vt_score, reputation_status
            FROM domains 
            WHERE domain = ?
        """, (domain,))
        return self.cursor.fetchone()
    
    def get_ip_reputation(self, ip):
        """Получение репутации IP"""
        if not ip:
            return None
        self.cursor.execute("""
            SELECT vt_malicious, vt_suspicious, vt_score, reputation_status, country, asn
            FROM ip_addresses 
            WHERE ip = ?
        """, (ip,))
        return self.cursor.fetchone()
    
    def get_cloud_storage_links(self, file_number=None):
        """Получение ссылок на облачные хранилища"""
        if file_number:
            self.cursor.execute("""
                SELECT url, storage_type, file_number, sender_email, subject, detected_at
                FROM cloud_storage_urls 
                WHERE file_number = ?
                ORDER BY detected_at DESC
            """, (file_number,))
        else:
            self.cursor.execute("""
                SELECT url, storage_type, file_number, sender_email, subject, detected_at
                FROM cloud_storage_urls 
                ORDER BY detected_at DESC
                LIMIT 100
            """)
        return self.cursor.fetchall()
    
    def print_email(self, email, index, total):
        """Красивый вывод одного письма с репутацией и вложениями"""
        
        (file_num, subject, domain, sender_email, ip, has_attach, date, body, urls_json) = email
        
        # Парсим ссылки
        urls = []
        if urls_json:
            try:
                urls = json.loads(urls_json)
            except:
                if urls_json and urls_json != '[]':
                    urls = [urls_json]
        
        # Получаем репутацию домена
        domain_rep = self.get_domain_reputation(domain) if domain else None
        
        # Получаем репутацию IP
        ip_rep = self.get_ip_reputation(ip) if ip else None
        
        # Получаем вложения
        attachments = self.get_email_attachments(file_num) if has_attach else []
        
        # Получаем ссылки на облачные хранилища
        cloud_links = self.get_cloud_storage_links(file_num)
        
        print(f"\n{Colors.CYAN}{'='*100}{Colors.END}")
        print(f"{Colors.BOLD}📧 Письмо {index + 1} из {total}{Colors.END}")
        print(f"{Colors.CYAN}{'='*100}{Colors.END}")
        
        # Номер файла
        print(f"{Colors.YELLOW}📁 Номер файла:{Colors.END} {file_num}.eml")
        
        # Отправитель
        if sender_email:
            print(f"{Colors.YELLOW}👤 Отправитель:{Colors.END} {Colors.GREEN}{sender_email}{Colors.END}")
        elif domain:
            print(f"{Colors.YELLOW}👤 Отправитель:{Colors.END} {Colors.GREEN}{domain}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}👤 Отправитель:{Colors.END} {Colors.DIM}не указан{Colors.END}")
        
        # Домен с репутацией
        if domain:
            rep_icon = self.get_reputation_icon(domain_rep[7] if domain_rep else 'unknown')
            print(f"{Colors.YELLOW}🌐 Домен:{Colors.END} {domain} {rep_icon}")
            
            if domain_rep:
                spf_color = self.get_auth_status_color(domain_rep[0])
                dkim_color = self.get_auth_status_color(domain_rep[1])
                dmarc_color = self.get_auth_status_color(domain_rep[2])
                print(f"{Colors.YELLOW}   Аутентификация:{Colors.END} "
                      f"SPF: {spf_color}{domain_rep[0] or '?'}{Colors.END}, "
                      f"DKIM: {dkim_color}{domain_rep[1] or '?'}{Colors.END}, "
                      f"DMARC: {dmarc_color}{domain_rep[2] or '?'}{Colors.END} "
                      f"(score: {domain_rep[3]})")
                
                if domain_rep[4] > 0 or domain_rep[5] > 0:
                    print(f"{Colors.YELLOW}   VirusTotal:{Colors.END} "
                          f"{Colors.RED}malicious: {domain_rep[4]}{Colors.END}, "
                          f"{Colors.YELLOW}suspicious: {domain_rep[5]}{Colors.END}")
        
        # Тема
        print(f"{Colors.YELLOW}📝 Тема:{Colors.END} {Colors.BOLD}{subject or '(без темы)'}{Colors.END}")
        
        # IP с репутацией
        if ip:
            ip_icon = self.get_reputation_icon(ip_rep[3] if ip_rep else 'unknown')
            print(f"{Colors.YELLOW}🖧 IP адрес:{Colors.END} {ip} {ip_icon}")
            if ip_rep and (ip_rep[0] > 0 or ip_rep[1] > 0):
                print(f"{Colors.YELLOW}   VirusTotal:{Colors.END} "
                      f"{Colors.RED}malicious: {ip_rep[0]}{Colors.END}, "
                      f"{Colors.YELLOW}suspicious: {ip_rep[1]}{Colors.END}")
            if ip_rep and ip_rep[4]:
                print(f"{Colors.YELLOW}   Гео:{Colors.END} {ip_rep[4]} {ip_rep[5] if ip_rep[5] else ''}")
        else:
            print(f"{Colors.YELLOW}🖧 IP адрес:{Colors.END} {Colors.DIM}не определен{Colors.END}")
        
        # Дата
        date_display = date if date else 'не указана'
        try:
            if date:
                date_obj = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %z')
                date_display = date_obj.strftime('%d.%m.%Y %H:%M:%S')
        except:
            pass
        print(f"{Colors.YELLOW}📅 Дата:{Colors.END} {date_display}")
        
        # Вложение
        if has_attach:
            print(f"{Colors.YELLOW}📎 Вложение:{Colors.END} {Colors.GREEN}✓ Да{Colors.END}")
            if attachments:
                print(f"{Colors.DIM}{'─'*80}{Colors.END}")
                print(f"{Colors.BOLD}   Вложения:{Colors.END}")
                for attach in attachments:
                    filename, ctype, size, md5, sha1, sha256, vt_mal, vt_sus, vt_score, rep = attach
                    rep_icon = self.get_reputation_icon(rep)
                    size_kb = size / 1024 if size < 1024 * 1024 else size / (1024 * 1024)
                    size_unit = "KB" if size < 1024 * 1024 else "MB"
                    
                    print(f"   📄 {Colors.CYAN}{filename}{Colors.END} ({size_kb:.1f} {size_unit}) {rep_icon}")
                    if vt_mal > 0:
                        print(f"      🦠 VT: {Colors.RED}{vt_mal} malicious{Colors.END}, {vt_sus} suspicious")
                    print(f"      🔑 SHA256: {sha256[:16]}...")
        else:
            print(f"{Colors.YELLOW}📎 Вложение:{Colors.END} {Colors.DIM}✗ Нет{Colors.END}")
        
        # Ссылки на облачные хранилища
        if cloud_links:
            print(f"\n{Colors.YELLOW}☁️ Ссылки на облачные хранилища ({len(cloud_links)}):{Colors.END}")
            print(f"{Colors.DIM}{'─'*80}{Colors.END}")
            for i, cloud in enumerate(cloud_links, 1):
                url, storage_type, fnum, semail, subj, detected = cloud
                escaped_url = self.escape_url(url)
                print(f"  {i:2}. [{storage_type}] {Colors.CYAN}{escaped_url}{Colors.END}")
            print(f"{Colors.DIM}{'─'*80}{Colors.END}")
        
        # Обычные ссылки
        if urls:
            print(f"\n{Colors.YELLOW}🔗 Другие ссылки в письме ({len(urls)}):{Colors.END}")
            print(f"{Colors.DIM}{'─'*80}{Colors.END}")
            for i, url in enumerate(urls, 1):
                escaped_url = self.escape_url(url)
                print(f"  {i:2}. {Colors.CYAN}{escaped_url}{Colors.END}")
            print(f"{Colors.DIM}{'─'*80}{Colors.END}")
        elif not cloud_links:
            print(f"\n{Colors.YELLOW}🔗 Ссылки в письме:{Colors.END} {Colors.DIM}нет{Colors.END}")
        
        # Текст письма
        print(f"\n{Colors.YELLOW}📄 Текст письма:{Colors.END}")
        print(f"{Colors.DIM}{'─'*80}{Colors.END}")
        
        if body and body.strip():
            lines = body.split('\n')
            line_count = 0
            for line in lines:
                if len(line) > 100:
                    line = line[:100] + "..."
                print(f"  {line}")
                line_count += 1
                if line_count > 30:
                    print(f"  {Colors.DIM}... (текст обрезан, полная версия в файле){Colors.END}")
                    break
        else:
            print(f"  {Colors.DIM}(текст отсутствует){Colors.END}")
        
        print(f"{Colors.DIM}{'─'*80}{Colors.END}")
    
    def interactive_view(self, emails):
        """Интерактивный просмотр писем"""
        
        if not emails:
            print(f"{Colors.RED}❌ Письма не найдены{Colors.END}")
            return
        
        total = len(emails)
        current = 0
        
        while True:
            os.system('clear')
            
            print(f"{Colors.BOLD}{Colors.CYAN}📧 Просмотр писем пользователя{Colors.END}")
            print(f"{Colors.DIM}Всего писем: {total} | Текущее: {current + 1}{Colors.END}")
            print()
            
            self.print_email(emails[current], current, total)
            
            print(f"\n{Colors.YELLOW}Навигация:{Colors.END}")
            print(f"  {Colors.GREEN}[n]{Colors.END} или {Colors.GREEN}[→]{Colors.END}  - следующее письмо")
            print(f"  {Colors.GREEN}[p]{Colors.END} или {Colors.GREEN}[←]{Colors.END}  - предыдущее письмо")
            print(f"  {Colors.GREEN}[j]{Colors.END} - перейти к письму по номеру")
            print(f"  {Colors.GREEN}[s]{Colors.END} - сохранить текущее письмо в файл")
            print(f"  {Colors.GREEN}[a]{Colors.END} - сохранить все письма в папку")
            print(f"  {Colors.GREEN}[f]{Colors.END} - найти в тексте")
            print(f"  {Colors.GREEN}[u]{Colors.END} - открыть ссылку")
            print(f"  {Colors.GREEN}[v]{Colors.END} - показать вложения")
            print(f"  {Colors.GREEN}[c]{Colors.END} - показать облачные хранилища")
            print(f"  {Colors.GREEN}[q]{Colors.END} - выход")
            
            choice = input(f"\n{Colors.BOLD}Выберите действие: {Colors.END}").strip().lower()
            
            if choice in ['n', '→', 'right']:
                if current < total - 1:
                    current += 1
                else:
                    print(f"\n{Colors.YELLOW}⚠️ Это последнее письмо{Colors.END}")
                    input("Нажмите Enter...")
            
            elif choice in ['p', '←', 'left']:
                if current > 0:
                    current -= 1
                else:
                    print(f"\n{Colors.YELLOW}⚠️ Это первое письмо{Colors.END}")
                    input("Нажмите Enter...")
            
            elif choice == 'j':
                try:
                    num = int(input(f"Введите номер письма (1-{total}): "))
                    if 1 <= num <= total:
                        current = num - 1
                    else:
                        print(f"{Colors.RED}❌ Неверный номер{Colors.END}")
                        input("Нажмите Enter...")
                except ValueError:
                    print(f"{Colors.RED}❌ Введите число{Colors.END}")
                    input("Нажмите Enter...")
            
            elif choice == 's':
                self.save_email(emails[current])
            
            elif choice == 'a':
                self.save_all_emails(emails)
            
            elif choice == 'f':
                self.search_in_text(emails)
            
            elif choice == 'u':
                self.open_url_from_email(emails[current])
            
            elif choice == 'v':
                self.show_attachments_for_email(emails[current])
            
            elif choice == 'c':
                self.show_cloud_storage_for_email(emails[current])
            
            elif choice == 'q':
                print(f"\n{Colors.GREEN}👋 До свидания!{Colors.END}")
                break
    
    def show_cloud_storage_for_email(self, email):
        """Показать ссылки на облачные хранилища для текущего письма"""
        file_num = email[0]
        cloud_links = self.get_cloud_storage_links(file_num)
        
        if not cloud_links:
            print(f"\n{Colors.YELLOW}⚠️ В этом письме нет ссылок на облачные хранилища{Colors.END}")
            input("Нажмите Enter...")
            return
        
        os.system('clear')
        print(f"{Colors.BOLD}{Colors.CYAN}☁️ Ссылки на облачные хранилища в письме {file_num}.eml{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")
        
        for i, cloud in enumerate(cloud_links, 1):
            url, storage_type, fnum, sender_email, subject, detected = cloud
            print(f"{Colors.BOLD}{i}. {Colors.GREEN}[{storage_type}]{Colors.END}")
            print(f"   URL: {self.escape_url(url)}")
            print(f"   Отправитель: {sender_email or '—'}")
            print(f"   Тема: {subject[:80] if subject else '—'}")
            print(f"   Обнаружено: {detected[:16] if detected else '—'}")
            print()
        
        input(f"{Colors.DIM}Нажмите Enter для продолжения...{Colors.END}")
    
    def show_attachments_for_email(self, email):
        """Показать вложения для текущего письма"""
        file_num = email[0]
        attachments = self.get_email_attachments(file_num)
        
        if not attachments:
            print(f"\n{Colors.YELLOW}⚠️ В этом письме нет вложений{Colors.END}")
            input("Нажмите Enter...")
            return
        
        os.system('clear')
        print(f"{Colors.BOLD}{Colors.CYAN}📎 Вложения в письме {file_num}.eml{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")
        
        for i, attach in enumerate(attachments, 1):
            filename, ctype, size, md5, sha1, sha256, vt_mal, vt_sus, vt_score, rep = attach
            size_kb = size / 1024 if size < 1024 * 1024 else size / (1024 * 1024)
            size_unit = "KB" if size < 1024 * 1024 else "MB"
            rep_icon = self.get_reputation_icon(rep)
            
            print(f"{Colors.BOLD}{i}. {Colors.CYAN}{filename}{Colors.END} {rep_icon}")
            print(f"   Тип: {ctype}")
            print(f"   Размер: {size_kb:.1f} {size_unit}")
            print(f"   MD5: {md5}")
            print(f"   SHA1: {sha1}")
            print(f"   SHA256: {sha256}")
            if vt_mal > 0 or vt_sus > 0:
                print(f"   🦠 VirusTotal: {Colors.RED}malicious: {vt_mal}{Colors.END}, suspicious: {vt_sus}")
            print()
        
        input(f"{Colors.DIM}Нажмите Enter для продолжения...{Colors.END}")
    
    def open_url_from_email(self, email):
        """Открытие ссылки из письма"""
        (file_num, subject, domain, sender_email, ip, has_attach, date, body, urls_json) = email
        
        urls = []
        if urls_json:
            try:
                urls = json.loads(urls_json)
            except:
                if urls_json and urls_json != '[]':
                    urls = [urls_json]
        
        # Добавляем облачные ссылки
        cloud_links = self.get_cloud_storage_links(file_num)
        for cloud in cloud_links:
            urls.append(cloud[0])
        
        if not urls:
            print(f"\n{Colors.YELLOW}⚠️ В этом письме нет ссылок{Colors.END}")
            input("Нажмите Enter...")
            return
        
        print(f"\n{Colors.CYAN}🔗 Ссылки в письме:{Colors.END}")
        for i, url in enumerate(urls, 1):
            url_display = self.escape_url(url)
            # Отмечаем облачные ссылки
            is_cloud = any(cloud[0] == url for cloud in cloud_links)
            prefix = "☁️ " if is_cloud else "🔗 "
            print(f"  {i:2}. {prefix}{Colors.GREEN}{url_display}{Colors.END}")
        
        choice = input(f"\n{Colors.BOLD}Выберите номер ссылки (или Enter для выхода): {Colors.END}").strip()
        
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(urls):
                url = urls[idx]
                print(f"\n{Colors.GREEN}🌐 Открываю: {url}{Colors.END}")
                os.system(f"xdg-open '{url}'")
    
    def save_email(self, email):
        """Сохранение письма в файл"""
        (file_num, subject, domain, sender_email, ip, has_attach, date, body, urls_json) = email
        
        if sender_email:
            safe_sender = sender_email.replace('@', '_').replace('.', '_')
        else:
            safe_sender = domain.replace('.', '_') if domain else "unknown"
        
        safe_subject = "".join(c for c in (subject or "no_subject") if c.isalnum() or c in (' ', '-', '_')).strip()[:50]
        filename = f"email_{file_num}_{safe_sender}_{safe_subject}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Файл: {file_num}.eml\n")
            f.write(f"Отправитель: {sender_email or domain or 'не указан'}\n")
            if sender_email:
                f.write(f"Email: {sender_email}\n")
            if domain:
                f.write(f"Домен: {domain}\n")
                
                # Добавляем репутацию домена
                domain_rep = self.get_domain_reputation(domain)
                if domain_rep:
                    f.write(f"\n=== РЕПУТАЦИЯ ДОМЕНА ===\n")
                    f.write(f"SPF: {domain_rep[0]}\n")
                    f.write(f"DKIM: {domain_rep[1]}\n")
                    f.write(f"DMARC: {domain_rep[2]}\n")
                    f.write(f"Auth Score: {domain_rep[3]}\n")
                    f.write(f"VT Malicious: {domain_rep[4]}\n")
                    f.write(f"VT Suspicious: {domain_rep[5]}\n")
                    f.write(f"Reputation: {domain_rep[7]}\n")
            
            f.write(f"Тема: {subject or '(без темы)'}\n")
            f.write(f"IP: {ip or 'не определен'}\n")
            
            # Репутация IP
            if ip:
                ip_rep = self.get_ip_reputation(ip)
                if ip_rep and (ip_rep[0] > 0 or ip_rep[1] > 0):
                    f.write(f"IP Reputation: malicious={ip_rep[0]}, suspicious={ip_rep[1]}\n")
            
            f.write(f"Дата: {date or 'не указана'}\n")
            f.write(f"Вложение: {'Да' if has_attach else 'Нет'}\n")
            
            # Вложения
            if has_attach:
                attachments = self.get_email_attachments(file_num)
                if attachments:
                    f.write(f"\n=== ВЛОЖЕНИЯ ===\n")
                    for attach in attachments:
                        filename_a, ctype, size, md5, sha1, sha256, vt_mal, vt_sus, vt_score, rep = attach
                        f.write(f"\nФайл: {filename_a}\n")
                        f.write(f"  Тип: {ctype}\n")
                        f.write(f"  Размер: {size} bytes\n")
                        f.write(f"  MD5: {md5}\n")
                        f.write(f"  SHA1: {sha1}\n")
                        f.write(f"  SHA256: {sha256}\n")
                        if vt_mal > 0 or vt_sus > 0:
                            f.write(f"  VT: malicious={vt_mal}, suspicious={vt_sus}\n")
            
            # Ссылки на облачные хранилища
            cloud_links = self.get_cloud_storage_links(file_num)
            if cloud_links:
                f.write(f"\n=== ССЫЛКИ НА ОБЛАЧНЫЕ ХРАНИЛИЩА ===\n")
                for cloud in cloud_links:
                    url, storage_type, fnum, semail, subj, detected = cloud
                    f.write(f"[{storage_type}] {url}\n")
            
            # Обычные ссылки
            if urls_json:
                try:
                    urls = json.loads(urls_json)
                    if urls:
                        f.write(f"\n=== ДРУГИЕ ССЫЛКИ ===\n")
                        for i, url in enumerate(urls, 1):
                            f.write(f"{i}. {url}\n")
                except:
                    pass
            
            f.write(f"\n=== ТЕКСТ ПИСЬМА ===\n\n")
            f.write(body or "(текст отсутствует)")
        
        print(f"\n{Colors.GREEN}✅ Письмо сохранено в: {filename}{Colors.END}")
        input("Нажмите Enter...")
    
    def save_all_emails(self, emails):
        """Сохранение всех писем в папку"""
        folder_name = f"emails_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(folder_name, exist_ok=True)
        
        for idx, email in enumerate(emails):
            (file_num, subject, domain, sender_email, ip, has_attach, date, body, urls_json) = email
            
            if sender_email:
                safe_sender = sender_email.replace('@', '_').replace('.', '_')
            else:
                safe_sender = domain.replace('.', '_') if domain else "unknown"
            
            safe_subject = "".join(c for c in (subject or "no_subject") if c.isalnum() or c in (' ', '-', '_')).strip()[:50]
            filename = f"{folder_name}/{file_num}_{safe_sender}_{safe_subject}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Файл: {file_num}.eml\n")
                f.write(f"Отправитель: {sender_email or domain or 'не указан'}\n")
                if sender_email:
                    f.write(f"Email: {sender_email}\n")
                if domain:
                    f.write(f"Домен: {domain}\n")
                f.write(f"Тема: {subject or '(без темы)'}\n")
                f.write(f"IP: {ip or 'не определен'}\n")
                f.write(f"Дата: {date or 'не указана'}\n")
                f.write(f"Вложение: {'Да' if has_attach else 'Нет'}\n")
                f.write(body or "(текст отсутствует)")
            
            if (idx + 1) % 10 == 0:
                print(f"  Сохранено {idx + 1}/{len(emails)} писем...")
        
        print(f"\n{Colors.GREEN}✅ Все письма ({len(emails)}) сохранены в папку: {folder_name}/{Colors.END}")
        input("Нажмите Enter...")
    
    def search_in_text(self, emails):
        """Поиск в тексте текущего списка писем"""
        search_term = input("Введите текст для поиска: ").strip().lower()
        if not search_term:
            return
        
        found = []
        for idx, email in enumerate(emails):
            (file_num, subject, domain, sender_email, ip, has_attach, date, body, urls_json) = email
            if body and search_term in body.lower():
                found.append((idx, file_num, subject, sender_email or domain))
        
        if found:
            print(f"\n{Colors.GREEN}✅ Найдено {len(found)} писем:{Colors.END}")
            for idx, file_num, subject, sender in found[:20]:
                print(f"  {idx + 1}. {file_num}.eml - {sender}: {subject[:50]}")
            
            if len(found) > 20:
                print(f"  ... и еще {len(found) - 20} писем")
            
            jump = input("\nПерейти к письму (введите номер): ")
            try:
                num = int(jump) - 1
                if 0 <= num < len(emails):
                    self.print_email(emails[num], num, len(emails))
                    input("\nНажмите Enter...")
            except:
                pass
        else:
            print(f"\n{Colors.YELLOW}⚠️ Ничего не найдено{Colors.END}")
            input("Нажмите Enter...")
    
    def show_compromised_indicators(self):
        """Показать засвеченные индикаторы"""
        self.cursor.execute("""
            SELECT type, value, reason, severity, detected_at
            FROM compromised 
            ORDER BY severity DESC, detected_at DESC
        """)
        data = self.cursor.fetchall()
        
        if not data:
            print(f"\n{Colors.GREEN}✅ Засвеченных индикаторов не обнаружено{Colors.END}")
            input("\nНажмите Enter...")
            return
        
        os.system('clear')
        print(f"{Colors.BOLD}{Colors.RED}🚨 ЗАСВЕЧЕННЫЕ ИНДИКАТОРЫ{Colors.END}")
        print(f"{Colors.RED}{'='*100}{Colors.END}\n")
        
        print(f"{Colors.BOLD}{'№':<4} {'Тип':<10} {'Значение':<45} {'Severity':<10} {'Дата':<20}{Colors.END}")
        print(f"{Colors.DIM}{'─'*100}{Colors.END}")
        
        for i, (typ, val, reason, sev, date) in enumerate(data, 1):
            sev_color = Colors.RED if sev == 'high' else Colors.YELLOW
            val_display = val[:42] + "..." if len(val) > 45 else val
            date_display = date[:16] if date else "unknown"
            print(f"{i:<4} {typ:<10} {val_display:<45} {sev_color}{sev:<10}{Colors.END} {date_display}")
        
        print(f"\n{Colors.DIM}{'─'*100}{Colors.END}")
        print(f"Всего засвеченных индикаторов: {len(data)}")
        
        input(f"\n{Colors.DIM}Нажмите Enter для продолжения...{Colors.END}")
    
    def show_cloud_storage_overview(self):
        """Показать обзор всех ссылок на облачные хранилища"""
        page = 0
        per_page = 50
        
        while True:
            offset = page * per_page
            self.cursor.execute("""
                SELECT url, storage_type, file_number, sender_email, subject, detected_at
                FROM cloud_storage_urls 
                ORDER BY detected_at DESC
                LIMIT ? OFFSET ?
            """, (per_page, offset))
            data = self.cursor.fetchall()
            
            if not data:
                print(f"\n{Colors.YELLOW}⚠️ Ссылок на облачные хранилища не найдено{Colors.END}")
                break
            
            # Получаем общее количество
            self.cursor.execute("SELECT COUNT(*) FROM cloud_storage_urls")
            total = self.cursor.fetchone()[0]
            total_pages = (total + per_page - 1) // per_page
            
            os.system('clear')
            print(f"{Colors.BOLD}{Colors.CYAN}☁️ ССЫЛКИ НА ОБЛАЧНЫЕ ХРАНИЛИЩА{Colors.END}")
            print(f"{Colors.CYAN}{'='*100}{Colors.END}")
            print(f"{Colors.DIM}Страница {page + 1} из {total_pages} | Всего ссылок: {total}{Colors.END}\n")
            
            print(f"{Colors.BOLD}{'№':<4} {'Файл':<6} {'Тип':<15} {'Отправитель':<25} {'Тема':<30} {'URL':<20}{Colors.END}")
            print(f"{Colors.DIM}{'─'*110}{Colors.END}")
            
            for i, (url, storage_type, file_num, sender_email, subject, detected) in enumerate(data, 1 + offset):
                url_disp = url[:17] + "..." if len(url) > 20 else url
                sender_disp = (sender_email or '—')[:22] + "..." if sender_email and len(sender_email) > 25 else (sender_email or '—')
                subject_disp = (subject or '—')[:27] + "..." if subject and len(subject) > 30 else (subject or '—')
                
                print(f"{i:<4} {file_num:<6} {Colors.GREEN}{storage_type[:13]:<15}{Colors.END} {sender_disp:<25} {subject_disp:<30} {url_disp}")
            
            print(f"\n{Colors.DIM}{'─'*110}{Colors.END}")
            print(f"\n{Colors.YELLOW}[n] след  [p] пред  [g] страница  [s] выбрать  [b] назад{Colors.END}")
            cmd = input(f"{Colors.BOLD}> {Colors.END}").strip().lower()
            
            if cmd == 'n' and page < total_pages - 1:
                page += 1
            elif cmd == 'p' and page > 0:
                page -= 1
            elif cmd == 'g':
                try:
                    p = int(input(f"Страница (1-{total_pages}): "))
                    if 1 <= p <= total_pages:
                        page = p - 1
                except:
                    pass
            elif cmd == 's':
                try:
                    idx = int(input("Введите номер записи для просмотра: ")) - 1 - offset
                    if 0 <= idx < len(data):
                        file_num = data[idx][2]
                        self.cursor.execute("""
                            SELECT * FROM emails WHERE file_number = ?
                        """, (file_num,))
                        email = self.cursor.fetchone()
                        if email:
                            self.interactive_view([email])
                except:
                    pass
            elif cmd == 'b':
                break
    
    def show_attachments_overview(self):
        """Показать обзор всех вложений с пагинацией"""
        page = 0
        per_page = 50
        
        while True:
            offset = page * per_page
            self.cursor.execute("""
                SELECT file_number, filename, content_type, size, 
                       vt_malicious, vt_suspicious, reputation_status
                FROM attachments 
                ORDER BY vt_malicious DESC, file_number
                LIMIT ? OFFSET ?
            """, (per_page, offset))
            data = self.cursor.fetchall()
            
            if not data:
                print(f"\n{Colors.YELLOW}⚠️ Вложений не найдено{Colors.END}")
                break
            
            self.cursor.execute("SELECT COUNT(*) FROM attachments")
            total = self.cursor.fetchone()[0]
            total_pages = (total + per_page - 1) // per_page
            
            os.system('clear')
            print(f"{Colors.BOLD}{Colors.CYAN}📎 ВСЕ ВЛОЖЕНИЯ{Colors.END}")
            print(f"{Colors.CYAN}{'='*100}{Colors.END}")
            print(f"{Colors.DIM}Страница {page + 1} из {total_pages} | Всего вложений: {total}{Colors.END}\n")
            
            print(f"{Colors.BOLD}{'Файл':<8} {'Имя файла':<35} {'Тип':<15} {'Размер':<10} {'VT':<8} {'Статус':<10}{Colors.END}")
            print(f"{Colors.DIM}{'─'*100}{Colors.END}")
            
            for file_num, filename, ctype, size, vt_mal, vt_sus, rep in data:
                size_kb = size / 1024 if size < 1024 * 1024 else size / (1024 * 1024)
                size_unit = "KB" if size < 1024 * 1024 else "MB"
                vt_str = f"{Colors.RED}{vt_mal}{Colors.END}/{vt_sus}" if vt_mal > 0 else f"{Colors.GREEN}0{Colors.END}/0"
                rep_icon = self.get_reputation_icon(rep)
                filename_disp = filename[:32] + "..." if len(filename) > 35 else filename
                
                print(f"{file_num:<8} {filename_disp:<35} {ctype[:12]:<15} {size_kb:.1f}{size_unit:<7} {vt_str:<8} {rep_icon} {rep}")
            
            print(f"\n{Colors.DIM}{'─'*100}{Colors.END}")
            print(f"\n{Colors.YELLOW}[n] след  [p] пред  [g] страница  [b] назад{Colors.END}")
            cmd = input(f"{Colors.BOLD}> {Colors.END}").strip().lower()
            
            if cmd == 'n' and page < total_pages - 1:
                page += 1
            elif cmd == 'p' and page > 0:
                page -= 1
            elif cmd == 'g':
                try:
                    p = int(input(f"Страница (1-{total_pages}): "))
                    if 1 <= p <= total_pages:
                        page = p - 1
                except:
                    pass
            elif cmd == 'b':
                break
    
    def show_domains_overview(self):
        """Показать обзор доменов с репутацией"""
        page = 0
        per_page = 50
        
        while True:
            offset = page * per_page
            self.cursor.execute("""
                SELECT domain, count, spf_status, dkim_status, dmarc_status,
                       vt_malicious, vt_suspicious, reputation_status
                FROM domains 
                ORDER BY vt_malicious DESC, count DESC
                LIMIT ? OFFSET ?
            """, (per_page, offset))
            data = self.cursor.fetchall()
            
            if not data:
                print(f"\n{Colors.YELLOW}⚠️ Данных о доменах нет{Colors.END}")
                break
            
            self.cursor.execute("SELECT COUNT(*) FROM domains")
            total = self.cursor.fetchone()[0]
            total_pages = (total + per_page - 1) // per_page
            
            os.system('clear')
            print(f"{Colors.BOLD}{Colors.CYAN}🌐 ДОМЕНЫ С РЕПУТАЦИЕЙ{Colors.END}")
            print(f"{Colors.CYAN}{'='*100}{Colors.END}")
            print(f"{Colors.DIM}Страница {page + 1} из {total_pages} | Всего доменов: {total}{Colors.END}\n")
            
            print(f"{Colors.BOLD}{'Домен':<40} {'Писем':<6} {'SPF':<6} {'DKIM':<6} {'DMARC':<6} {'VT':<10} {'Статус':<10}{Colors.END}")
            print(f"{Colors.DIM}{'─'*100}{Colors.END}")
            
            for domain, count, spf, dkim, dmarc, vt_mal, vt_sus, rep in data:
                spf_color = self.get_auth_status_color(spf)
                dkim_color = self.get_auth_status_color(dkim)
                dmarc_color = self.get_auth_status_color(dmarc)
                rep_icon = self.get_reputation_icon(rep)
                vt_str = f"{Colors.RED}{vt_mal}{Colors.END}/{vt_sus}" if vt_mal > 0 else f"{Colors.GREEN}0{Colors.END}/0"
                domain_disp = domain[:37] + "..." if len(domain) > 40 else domain
                
                print(f"{domain_disp:<40} {count:<6} {spf_color}{spf or '?'}{Colors.END:<6} "
                      f"{dkim_color}{dkim or '?'}{Colors.END:<6} {dmarc_color}{dmarc or '?'}{Colors.END:<6} "
                      f"{vt_str:<10} {rep_icon} {rep}")
            
            print(f"\n{Colors.DIM}{'─'*100}{Colors.END}")
            print(f"\n{Colors.YELLOW}[n] след  [p] пред  [g] страница  [s] выбрать  [b] назад{Colors.END}")
            cmd = input(f"{Colors.BOLD}> {Colors.END}").strip().lower()
            
            if cmd == 'n' and page < total_pages - 1:
                page += 1
            elif cmd == 'p' and page > 0:
                page -= 1
            elif cmd == 'g':
                try:
                    p = int(input(f"Страница (1-{total_pages}): "))
                    if 1 <= p <= total_pages:
                        page = p - 1
                except:
                    pass
            elif cmd == 's':
                try:
                    idx = int(input("Введите номер записи для просмотра: ")) - 1 - offset
                    if 0 <= idx < len(data):
                        domain = data[idx][0]
                        emails = self.search_emails(domain, "domain")
                        if emails:
                            self.interactive_view(emails)
                except:
                    pass
            elif cmd == 'b':
                break
    
    def get_statistics(self):
        """Получение общей статистики"""
        stats = {}
        
        self.cursor.execute("SELECT COUNT(*) FROM emails")
        stats['total_emails'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM emails WHERE has_attachment = 1")
        stats['with_attachments'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM emails WHERE extracted_urls IS NOT NULL AND extracted_urls != '' AND extracted_urls != '[]'")
        stats['with_urls'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM attachments")
        stats['total_attachments'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM attachments WHERE vt_malicious > 0")
        stats['malicious_attachments'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(DISTINCT sender_email) FROM senders WHERE sender_email IS NOT NULL")
        stats['unique_senders'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(DISTINCT sender_domain) FROM emails WHERE sender_domain IS NOT NULL")
        stats['unique_domains'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM compromised")
        stats['compromised'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM domains WHERE reputation_status = 'bad'")
        stats['bad_domains'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM ip_addresses WHERE vt_malicious > 0")
        stats['bad_ips'] = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM cloud_storage_urls")
        stats['cloud_links'] = self.cursor.fetchone()[0]
        
        return stats
    
    def show_statistics(self):
        """Показ расширенной статистики"""
        os.system('clear')
        print(f"{Colors.BOLD}{Colors.CYAN}📊 СТАТИСТИКА БАЗЫ ДАННЫХ{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")
        
        stats = self.get_statistics()
        
        print(f"{Colors.GREEN}📧 Всего писем:{Colors.END} {stats['total_emails']}")
        print(f"{Colors.GREEN}📎 С вложениями:{Colors.END} {stats['with_attachments']} ({stats['with_attachments']*100/stats['total_emails']:.1f}%)")
        print(f"{Colors.GREEN}🔗 Со ссылками:{Colors.END} {stats['with_urls']} ({stats['with_urls']*100/stats['total_emails']:.1f}%)")
        print(f"{Colors.GREEN}☁️ Ссылок на облачные хранилища:{Colors.END} {stats['cloud_links']}")
        print(f"{Colors.GREEN}📎 Всего вложений:{Colors.END} {stats['total_attachments']}")
        print(f"{Colors.GREEN}🦠 Вредоносных вложений:{Colors.END} {Colors.RED}{stats['malicious_attachments']}{Colors.END}")
        print(f"{Colors.GREEN}👥 Уникальных отправителей:{Colors.END} {stats['unique_senders']}")
        print(f"{Colors.GREEN}🌐 Уникальных доменов:{Colors.END} {stats['unique_domains']}")
        print(f"{Colors.GREEN}🚨 Засвеченных индикаторов:{Colors.END} {Colors.RED}{stats['compromised']}{Colors.END}")
        print(f"{Colors.GREEN}⚠️ Доменов с плохой репутацией:{Colors.END} {Colors.RED}{stats['bad_domains']}{Colors.END}")
        print(f"{Colors.GREEN}⚠️ Вредоносных IP:{Colors.END} {Colors.RED}{stats['bad_ips']}{Colors.END}")
        
        # Топ 10 отправителей
        print(f"\n{Colors.YELLOW}🏆 Топ 10 отправителей:{Colors.END}")
        self.cursor.execute("""
            SELECT sender_email, count, vt_malicious, reputation_status
            FROM senders 
            ORDER BY count DESC 
            LIMIT 10
        """)
        for i, (email, cnt, vt_mal, rep) in enumerate(self.cursor.fetchall(), 1):
            rep_icon = self.get_reputation_icon(rep)
            vt_str = f" {Colors.RED}🦠{vt_mal}{Colors.END}" if vt_mal > 0 else ""
            print(f"  {i:2}. {Colors.GREEN}{email[:40]}{Colors.END} - {cnt} писем{vt_str} {rep_icon}")
        
        # Топ 10 облачных хранилищ
        if stats['cloud_links'] > 0:
            print(f"\n{Colors.YELLOW}☁️ Топ 10 типов облачных хранилищ:{Colors.END}")
            self.cursor.execute("""
                SELECT storage_type, COUNT(*) as cnt
                FROM cloud_storage_urls 
                GROUP BY storage_type
                ORDER BY cnt DESC
                LIMIT 10
            """)
            for i, (stype, cnt) in enumerate(self.cursor.fetchall(), 1):
                print(f"  {i:2}. {Colors.CYAN}{stype}{Colors.END} - {cnt} ссылок")
        
        # Топ 10 вредоносных вложений
        if stats['malicious_attachments'] > 0:
            print(f"\n{Colors.RED}🦠 Топ 10 вредоносных вложений:{Colors.END}")
            self.cursor.execute("""
                SELECT filename, vt_malicious, reputation_status
                FROM attachments 
                WHERE vt_malicious > 0
                ORDER BY vt_malicious DESC 
                LIMIT 10
            """)
            for i, (name, vt_mal, rep) in enumerate(self.cursor.fetchall(), 1):
                print(f"  {i:2}. {Colors.RED}{name[:50]}{Colors.END} - {vt_mal} детекций")
        
        input(f"\n{Colors.DIM}Нажмите Enter для продолжения...{Colors.END}")
    
    def main_menu(self):
        """Главное меню"""
        if not self.connect():
            return
        
        while True:
            os.system('clear')
            print(f"{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗{Colors.END}")
            print(f"{Colors.BOLD}{Colors.CYAN}║     📧 Email Viewer - Анализ писем с репутацией              ║{Colors.END}")
            print(f"{Colors.BOLD}{Colors.CYAN}╚══════════════════════════════════════════════════════════════╝{Colors.END}")
            print()
            
            stats = self.get_statistics()
            print(f"{Colors.YELLOW}📊 Быстрая статистика:{Colors.END}")
            print(f"  📧 Писем: {stats['total_emails']} | 📎 Вложений: {stats['total_attachments']} | 🦠 Вредоносных: {Colors.RED}{stats['malicious_attachments']}{Colors.END}")
            print(f"  ☁️ Облачных ссылок: {stats['cloud_links']} | 🚨 Засвеченных: {Colors.RED}{stats['compromised']}{Colors.END}")
            print()
            
            print(f"{Colors.BOLD}Выберите действие:{Colors.END}")
            print(f"  {Colors.GREEN}[1]{Colors.END} - Поиск по email")
            print(f"  {Colors.GREEN}[2]{Colors.END} - Поиск по домену")
            print(f"  {Colors.GREEN}[3]{Colors.END} - Поиск по IP")
            print(f"  {Colors.GREEN}[4]{Colors.END} - 👥 Все отправители")
            print(f"  {Colors.GREEN}[5]{Colors.END} - 🌐 Все домены (с репутацией)")
            print(f"  {Colors.GREEN}[6]{Colors.END} - 📎 Все вложения")
            print(f"  {Colors.GREEN}[7]{Colors.END} - ☁️ Облачные хранилища")
            print(f"  {Colors.GREEN}[8]{Colors.END} - 🚨 Засвеченные индикаторы")
            print(f"  {Colors.GREEN}[9]{Colors.END} - 🔍 Фильтрация писем")
            print(f"  {Colors.GREEN}[0]{Colors.END} - 📊 Полная статистика")
            print(f"  {Colors.GREEN}[q]{Colors.END} - Выход")
            
            choice = input(f"\n{Colors.BOLD}Ваш выбор: {Colors.END}").strip()
            
            if choice == '1':
                term = input("Введите email: ").strip()
                if term:
                    emails = self.search_emails(term, "email")
                    if emails:
                        self.interactive_view(emails)
                    else:
                        print(f"{Colors.RED}❌ Письма не найдены{Colors.END}")
                        input("Нажмите Enter...")
            
            elif choice == '2':
                term = input("Введите домен: ").strip()
                if term:
                    emails = self.search_emails(term, "domain")
                    if emails:
                        self.interactive_view(emails)
                    else:
                        print(f"{Colors.RED}❌ Письма не найдены{Colors.END}")
                        input("Нажмите Enter...")
            
            elif choice == '3':
                term = input("Введите IP: ").strip()
                if term:
                    emails = self.search_emails(term, "ip")
                    if emails:
                        self.interactive_view(emails)
                    else:
                        print(f"{Colors.RED}❌ Письма не найдены{Colors.END}")
                        input("Нажмите Enter...")
            
            elif choice == '4':
                self.show_all_senders()
            
            elif choice == '5':
                self.show_domains_overview()
            
            elif choice == '6':
                self.show_attachments_overview()
            
            elif choice == '7':
                self.show_cloud_storage_overview()
            
            elif choice == '8':
                self.show_compromised_indicators()
            
            elif choice == '9':
                self.show_filter_menu()
            
            elif choice == '0':
                self.show_statistics()
            
            elif choice == 'q':
                print(f"\n{Colors.GREEN}👋 До свидания!{Colors.END}")
                break
    
    def show_all_senders(self):
        """Вывод списка отправителей с пагинацией"""
        page = 0
        per_page = 50
        
        while True:
            offset = page * per_page
            self.cursor.execute("""
                SELECT sender_email, sender_name, count, vt_malicious, vt_suspicious, reputation_status
                FROM senders 
                ORDER BY count DESC 
                LIMIT ? OFFSET ?
            """, (per_page, offset))
            senders = self.cursor.fetchall()
            
            if not senders:
                print(f"\n{Colors.YELLOW}⚠️ Нет данных{Colors.END}")
                break
            
            self.cursor.execute("SELECT COUNT(*) FROM senders")
            total = self.cursor.fetchone()[0]
            total_pages = (total + per_page - 1) // per_page
            
            os.system('clear')
            print(f"{Colors.BOLD}{Colors.CYAN}👥 СПИСОК ОТПРАВИТЕЛЕЙ{Colors.END}")
            print(f"{Colors.CYAN}{'='*100}{Colors.END}")
            print(f"{Colors.DIM}Страница {page + 1} из {total_pages} | Всего отправителей: {total}{Colors.END}\n")
            
            print(f"{Colors.BOLD}{'№':<4} {'Email':<40} {'Имя':<20} {'Писем':<6} {'VT':<8} {'Статус':<10}{Colors.END}")
            print(f"{Colors.DIM}{'─'*100}{Colors.END}")
            
            for i, (email, name, cnt, vt_mal, vt_sus, rep) in enumerate(senders, 1 + offset):
                rep_icon = self.get_reputation_icon(rep)
                vt_str = f"{Colors.RED}{vt_mal}{Colors.END}/{vt_sus}" if vt_mal > 0 else f"{Colors.GREEN}0{Colors.END}/0"
                name_disp = name[:17] + "..." if name and len(name) > 20 else (name or '—')
                email_disp = email[:37] + "..." if len(email) > 40 else email
                
                print(f"{i:<4} {Colors.GREEN}{email_disp:<40}{Colors.END} {name_disp:<20} {cnt:<6} {vt_str:<8} {rep_icon} {rep}")
            
            print(f"\n{Colors.DIM}{'─'*100}{Colors.END}")
            print(f"\n{Colors.YELLOW}[n] след  [p] пред  [g] страница  [s] выбрать  [b] назад{Colors.END}")
            cmd = input(f"{Colors.BOLD}> {Colors.END}").strip().lower()
            
            if cmd == 'n' and page < total_pages - 1:
                page += 1
            elif cmd == 'p' and page > 0:
                page -= 1
            elif cmd == 'g':
                try:
                    p = int(input(f"Страница (1-{total_pages}): "))
                    if 1 <= p <= total_pages:
                        page = p - 1
                except:
                    pass
            elif cmd == 's':
                try:
                    idx = int(input("Номер отправителя: ")) - 1 - offset
                    if 0 <= idx < len(senders):
                        email = senders[idx][0]
                        emails = self.search_emails(email, "email")
                        if emails:
                            self.interactive_view(emails)
                except:
                    pass
            elif cmd == 'b':
                break
    
    def show_filter_menu(self):
        """Меню фильтрации писем"""
        while True:
            os.system('clear')
            print(f"{Colors.BOLD}{Colors.CYAN}🔍 ФИЛЬТРАЦИЯ ПИСЕМ{Colors.END}")
            print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")
            
            print(f"{Colors.BOLD}Выберите фильтр:{Colors.END}")
            print(f"  {Colors.GREEN}[1]{Colors.END} - Только с вложениями")
            print(f"  {Colors.GREEN}[2]{Colors.END} - Только со ссылками")
            print(f"  {Colors.GREEN}[3]{Colors.END} - Только с вредоносными вложениями")
            print(f"  {Colors.GREEN}[4]{Colors.END} - Только с облачными хранилищами")
            print(f"  {Colors.GREEN}[5]{Colors.END} - Только от отправителей с плохой репутацией")
            print(f"  {Colors.GREEN}[b]{Colors.END} - Назад")
            
            choice = input(f"\n{Colors.BOLD}Ваш выбор: {Colors.END}").strip()
            
            if choice == '1':
                emails = self.search_emails("", "any", "attachments")
                if emails:
                    self.interactive_view(emails)
                else:
                    print(f"{Colors.YELLOW}⚠️ Писем с вложениями не найдено{Colors.END}")
                    input("Нажмите Enter...")
            
            elif choice == '2':
                emails = self.search_emails("", "any", "urls")
                if emails:
                    self.interactive_view(emails)
                else:
                    print(f"{Colors.YELLOW}⚠️ Писем со ссылками не найдено{Colors.END}")
                    input("Нажмите Enter...")
            
            elif choice == '3':
                self.cursor.execute("""
                    SELECT DISTINCT e.*
                    FROM emails e
                    JOIN attachments a ON e.file_number = a.file_number
                    WHERE a.vt_malicious > 0
                    ORDER BY e.file_number
                """)
                emails = self.cursor.fetchall()
                if emails:
                    self.interactive_view(emails)
                else:
                    print(f"{Colors.GREEN}✅ Вредоносных вложений не найдено{Colors.END}")
                    input("Нажмите Enter...")
            
            elif choice == '4':
                self.cursor.execute("""
                    SELECT DISTINCT e.*
                    FROM emails e
                    JOIN cloud_storage_urls c ON e.file_number = c.file_number
                    ORDER BY e.file_number
                """)
                emails = self.cursor.fetchall()
                if emails:
                    self.interactive_view(emails)
                else:
                    print(f"{Colors.YELLOW}⚠️ Писем со ссылками на облачные хранилища не найдено{Colors.END}")
                    input("Нажмите Enter...")
            
            elif choice == '5':
                self.cursor.execute("""
                    SELECT e.*
                    FROM emails e
                    WHERE e.sender_domain IN (
                        SELECT domain FROM domains WHERE reputation_status = 'bad'
                    )
                    ORDER BY e.file_number
                """)
                emails = self.cursor.fetchall()
                if emails:
                    self.interactive_view(emails)
                else:
                    print(f"{Colors.GREEN}✅ Отправителей с плохой репутацией не найдено{Colors.END}")
                    input("Нажмите Enter...")
            
            elif choice == 'b':
                break


def main():
    if len(sys.argv) < 2:
        print("Использование: python3 email_viewer.py <путь_к_базе_данных>")
        print("Пример: python3 email_viewer.py ./analysis_results/email_analysis.db")
        sys.exit(1)
    
    viewer = EmailViewer(sys.argv[1])
    try:
        viewer.main_menu()
    finally:
        viewer.close()


if __name__ == "__main__":
    main()
