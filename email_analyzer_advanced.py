#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
email_analyzer_advanced.py - Расширенный анализ email сообщений
Особенности:
- Поиск файлов от 1 до 10000
- Пропуск отсутствующих файлов с переходом к следующим
- Сохранение имени отправителя, email, домена и IP
- Извлечение и сохранение ссылок
- Извлечение вложений и их хешей (MD5, SHA1, SHA256)
- Проверка DKIM, DMARC, SPF
- Интеграция с VirusTotal для проверки репутации (домены, IP, хеши)
- Проверка ссылок на файловые хранилища (Google Drive, Dropbox, Mega и др.)
- Генерация HTML отчета с разделением по категориям угроз
"""

import os
import re
import csv
import email
import sqlite3
import json
import hashlib
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from collections import defaultdict, Counter
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# Попробуем импортировать дополнительные библиотеки с обработкой ошибок
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("⚠️ dnspython не установлен. Проверка DNS будет недоступна.")

try:
    import dkim
    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False
    print("⚠️ dkimpy не установлен. Проверка DKIM будет недоступна.")

try:
    from checkdmarc import get_dmarc_record, get_spf_record
    CHECKDMARC_AVAILABLE = True
except ImportError:
    CHECKDMARC_AVAILABLE = False
    print("⚠️ checkdmarc не установлен. Проверка SPF/DMARC будет ограничена.")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️ requests не установлен. Проверка VirusTotal будет недоступна.")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("⚠️ python-magic не установлен. Определение MIME типов будет ограничено.")


class EmailAnalyzerAdvanced:
    
    # Список известных файловых хранилищ
    CLOUD_STORAGE_DOMAINS = {
        # Google
        'google.com', 'drive.google.com', 'drive.usercontent.google.com',
        # Dropbox
        'dropbox.com', 'dropboxusercontent.com', 'db.tt',
        # Microsoft OneDrive
        'onedrive.live.com', '1drv.ms', 'onedrive.com', 'sharepoint.com',
        # Apple iCloud
        'icloud.com', 'icloud-content.com',
        # Box
        'box.com', 'app.box.com', 'boxcloud.com',
        # Mega
        'mega.nz', 'mega.co.nz', 'mega.io',
        # Яндекс.Диск
        'yandex.ru', 'yadi.sk', 'disk.yandex.ru', 'disk.yandex.net',
        # Mail.ru Cloud
        'mail.ru', 'cloud.mail.ru',
        # Облако Mail.ru
        'cloud.ru', 'cloud.ru',
        # pCloud
        'pcloud.com', 'e.pcloud.link',
        # Sync.com
        'sync.com',
        # MediaFire
        'mediafire.com', 'mediafire.net',
        # 4shared
        '4shared.com', '4shared.net',
        # Файлообменники
        'rapidgator.net', 'rg.to',
        'turbobit.net', 'turbo.to',
        'nitroflare.com', 'nitro.download',
        'uploaded.net', 'ul.to',
        'zippyshare.com', 'zippyshare.net',
        'sendspace.com', 'sendspace.net',
        'filefactory.com', 'filefactory.net',
        'hotlink.cc',
        'gigapeta.com', 'gigapeta.net',
        'dfiles.ru', 'depositfiles.com',
        'hitfile.net',
        'letitbit.net',
        'vip-file.com', 'vip-file.net',
        # Российские
        'sberdisk.ru', 'sberdisk.com',
        'cloud.mail.ru',
        'disk.yandex.ru', 'disk.yandex.net'
    }
    
    def __init__(self, eml_dir, output_dir, max_files=10000, skip_check=5, 
                 vt_api_key=None, online_mode=False, extract_attachments=False):
        self.eml_dir = Path(eml_dir)
        self.output_dir = Path(output_dir)
        self.max_files = max_files
        self.skip_check = skip_check
        self.vt_api_key = vt_api_key
        self.online_mode = online_mode
        self.extract_attachments = extract_attachments
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Создаем папку для вложений
        self.attachments_dir = self.output_dir / "attachments"
        if self.extract_attachments:
            self.attachments_dir.mkdir(parents=True, exist_ok=True)
        
        # База данных SQLite
        self.db_path = self.output_dir / "email_analysis.db"
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Счетчики
        self.domain_counter = Counter()
        self.ip_counter = Counter()
        self.url_counter = Counter()
        self.emails_data = []
        self.missing_files = []
        self.all_urls = set()
        self.attachments_data = []
        self.cloud_storage_urls = []
        
        # Для хранения результатов проверок
        self.domain_auth_cache = {}
        self.domain_vt_cache = {}
        self.ip_vt_cache = {}
        self.hash_vt_cache = {}
        
        # Регулярные выражения
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_pattern = re.compile(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
        self.email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        self.url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w$.+!*\'(),;:@&=?/~#%]*)?', re.IGNORECASE)
        
        self.setup_database()
    
    def get_storage_type(self, url):
        """Определение типа файлового хранилища по URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Убираем www. если есть
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Проверяем соответствие с известными хранилищами
            for storage in self.CLOUD_STORAGE_DOMAINS:
                if storage in domain or domain in storage:
                    if 'google' in storage and 'drive' in storage:
                        return 'Google Drive'
                    elif 'dropbox' in storage:
                        return 'Dropbox'
                    elif 'onedrive' in storage or '1drv' in storage or 'sharepoint' in storage:
                        return 'OneDrive'
                    elif 'icloud' in storage:
                        return 'iCloud'
                    elif 'box' in storage:
                        return 'Box'
                    elif 'mega' in storage:
                        return 'Mega.nz'
                    elif 'yandex' in storage or 'yadi' in storage:
                        return 'Yandex.Disk'
                    elif 'mail.ru' in storage or 'cloud.mail.ru' in storage:
                        return 'Mail.ru Cloud'
                    elif 'mediafire' in storage:
                        return 'MediaFire'
                    elif '4shared' in storage:
                        return '4shared'
                    elif 'rapidgator' in storage:
                        return 'RapidGator'
                    elif 'turbobit' in storage:
                        return 'TurboBit'
                    elif 'nitroflare' in storage:
                        return 'NitroFlare'
                    elif 'uploaded' in storage:
                        return 'Uploaded'
                    elif 'zippyshare' in storage:
                        return 'ZippyShare'
                    elif 'sendspace' in storage:
                        return 'SendSpace'
                    elif 'depositfiles' in storage or 'dfiles' in storage:
                        return 'DepositFiles'
                    elif 'sberdisk' in storage:
                        return 'SberDisk'
                    elif 'pcloud' in storage:
                        return 'pCloud'
                    else:
                        return storage.split('.')[0].capitalize()
        except:
            pass
        return None
    
    def setup_database(self):
        """Создание таблиц в SQLite"""
        
        # Основная таблица emails
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_number INTEGER,
                filename TEXT,
                sender_name TEXT,
                sender_email TEXT,
                sender_domain TEXT,
                sender_ip TEXT,
                subject TEXT,
                has_attachment INTEGER,
                body_text TEXT,
                message_date TEXT,
                extracted_urls TEXT,
                cloud_urls TEXT,
                file_exists INTEGER
            )
        ''')
        
        # Добавляем недостающие колонки
        self.cursor.execute("PRAGMA table_info(emails)")
        existing_columns = [col[1] for col in self.cursor.fetchall()]
        
        for col in ['sender_name', 'sender_email', 'extracted_urls', 'cloud_urls']:
            if col not in existing_columns:
                try:
                    self.cursor.execute(f"ALTER TABLE emails ADD COLUMN {col} TEXT")
                except:
                    pass
        
        # Таблица вложений
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                file_number INTEGER,
                filename TEXT,
                content_type TEXT,
                size INTEGER,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                vt_malicious INTEGER,
                vt_suspicious INTEGER,
                vt_score INTEGER,
                reputation_status TEXT,
                detected_names TEXT,
                last_checked TEXT,
                FOREIGN KEY (email_id) REFERENCES emails(id)
            )
        ''')
        
        # Таблица отправителей
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS senders (
                sender_email TEXT PRIMARY KEY,
                sender_name TEXT,
                count INTEGER,
                domain TEXT,
                spf_status TEXT,
                dkim_status TEXT,
                dmarc_status TEXT,
                auth_score INTEGER,
                vt_malicious INTEGER,
                vt_suspicious INTEGER,
                vt_score INTEGER,
                reputation_status TEXT,
                last_checked TEXT
            )
        ''')
        
        # Таблица доменов
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains (
                domain TEXT PRIMARY KEY,
                count INTEGER,
                spf_status TEXT,
                dkim_status TEXT,
                dmarc_status TEXT,
                auth_score INTEGER,
                vt_malicious INTEGER,
                vt_suspicious INTEGER,
                vt_score INTEGER,
                reputation_status TEXT,
                last_checked TEXT
            )
        ''')
        
        # Таблица IP адресов
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_addresses (
                ip TEXT PRIMARY KEY,
                count INTEGER,
                vt_malicious INTEGER,
                vt_suspicious INTEGER,
                vt_score INTEGER,
                reputation_status TEXT,
                country TEXT,
                asn TEXT,
                last_checked TEXT
            )
        ''')
        
        # Таблица для засвеченных объектов
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS compromised (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                value TEXT,
                reason TEXT,
                severity TEXT,
                detected_at TEXT
            )
        ''')
        
        # Таблица для хешей
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hashes (
                hash TEXT PRIMARY KEY,
                hash_type TEXT,
                vt_malicious INTEGER,
                vt_suspicious INTEGER,
                vt_score INTEGER,
                reputation_status TEXT,
                file_type TEXT,
                first_seen TEXT,
                last_checked TEXT
            )
        ''')
        
        # Таблица для URL
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                url TEXT PRIMARY KEY,
                domain TEXT,
                protocol TEXT,
                count INTEGER,
                first_seen TEXT,
                last_seen TEXT
            )
        ''')
        
        # Таблица для ссылок на облачные хранилища
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloud_storage_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                storage_type TEXT,
                file_number INTEGER,
                sender_email TEXT,
                subject TEXT,
                detected_at TEXT
            )
        ''')
        
        # Таблица для логов сканирования
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT,
                file_number INTEGER,
                status TEXT,
                message TEXT
            )
        ''')
        
        self.conn.commit()
    
    def extract_attachment_hashes(self, part, email_id, file_number):
        """Извлечение хешей из вложения"""
        filename = part.get_filename()
        if not filename:
            return None
        
        # Декодируем имя файла
        try:
            from email.header import decode_header
            decoded_header = decode_header(filename)
            filename = ''
            for content, encoding in decoded_header:
                if isinstance(content, bytes):
                    filename += content.decode(encoding or 'utf-8', errors='ignore')
                else:
                    filename += content
        except:
            pass
        
        # Получаем содержимое
        try:
            payload = part.get_payload(decode=True)
            if not payload:
                return None
            
            # Сохраняем файл если нужно
            if self.extract_attachments:
                safe_filename = re.sub(r'[^\w\-_\.]', '_', filename)
                filepath = self.attachments_dir / f"{file_number}_{safe_filename}"
                with open(filepath, 'wb') as f:
                    f.write(payload)
                saved_path = str(filepath)
            else:
                saved_path = None
            
            # Вычисляем хеши
            md5_hash = hashlib.md5(payload).hexdigest()
            sha1_hash = hashlib.sha1(payload).hexdigest()
            sha256_hash = hashlib.sha256(payload).hexdigest()
            
            # Определяем тип файла
            if MAGIC_AVAILABLE:
                try:
                    mime = magic.from_buffer(payload[:1024], mime=True)
                except:
                    mime = part.get_content_type()
            else:
                mime = part.get_content_type()
            
            attachment_info = {
                'email_id': email_id,
                'file_number': file_number,
                'filename': filename,
                'content_type': mime,
                'size': len(payload),
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash,
                'saved_path': saved_path
            }
            
            return attachment_info
            
        except Exception as e:
            print(f"    ⚠️ Ошибка при извлечении вложения {filename}: {e}")
            return None
    
    def check_virustotal_hash(self, file_hash):
        """Проверка хеша через VirusTotal"""
        if not self.vt_api_key or not self.online_mode or not REQUESTS_AVAILABLE:
            return {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'unknown'}
        
        if file_hash in self.hash_vt_cache:
            return self.hash_vt_cache[file_hash]
        
        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                
                result = {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'score': 100 - min(100, (malicious + suspicious) * 10),
                    'status': 'clean' if malicious == 0 else 'malicious' if malicious > 5 else 'suspicious'
                }
            elif response.status_code == 404:
                result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'not_found'}
            else:
                result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'error'}
                
        except Exception as e:
            result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'error'}
        
        self.hash_vt_cache[file_hash] = result
        return result
    
    def check_spf_dmarc_dkim(self, domain):
        """Проверка SPF, DMARC, DKIM для домена"""
        if not DNS_AVAILABLE:
            return {'spf': {'status': 'unknown'}, 'dkim': {'status': 'unknown'}, 
                    'dmarc': {'status': 'unknown'}, 'score': 0, 'status': 'unknown'}
        
        if domain in self.domain_auth_cache:
            return self.domain_auth_cache[domain]
        
        result = {
            'spf': {'status': 'unknown', 'details': None},
            'dmarc': {'status': 'unknown', 'details': None},
            'dkim': {'status': 'unknown', 'details': None},
            'score': 0,
            'status': 'unknown'
        }
        
        # Проверка SPF
        try:
            if CHECKDMARC_AVAILABLE:
                spf = get_spf_record(domain)
                if spf and spf.get('record'):
                    result['spf']['status'] = 'valid'
                    result['spf']['details'] = spf['record']
                    result['score'] += 30
                else:
                    result['spf']['status'] = 'invalid'
            else:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt = str(rdata)
                    if 'v=spf1' in txt:
                        result['spf']['status'] = 'valid'
                        result['spf']['details'] = txt
                        result['score'] += 30
                        break
                if result['spf']['status'] == 'unknown':
                    result['spf']['status'] = 'not_found'
        except Exception as e:
            result['spf']['status'] = 'error'
        
        # Проверка DMARC
        try:
            if CHECKDMARC_AVAILABLE:
                dmarc = get_dmarc_record(domain)
                if dmarc and dmarc.get('record'):
                    result['dmarc']['status'] = 'valid'
                    result['dmarc']['details'] = dmarc['record']
                    result['score'] += 40 if 'p=reject' in dmarc['record'] else 30
                else:
                    result['dmarc']['status'] = 'not_found'
            else:
                answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for rdata in answers:
                    txt = str(rdata)
                    if 'v=DMARC1' in txt:
                        result['dmarc']['status'] = 'valid'
                        result['dmarc']['details'] = txt
                        result['score'] += 40 if 'p=reject' in txt else 30
                        break
                if result['dmarc']['status'] == 'unknown':
                    result['dmarc']['status'] = 'not_found'
        except Exception as e:
            result['dmarc']['status'] = 'error'
        
        # Проверка DKIM
        try:
            selectors = ['default', 'google', 'selector1', 'selector2', 'dkim', 'mail', 'k1', 'k2']
            found = False
            for sel in selectors:
                try:
                    answers = dns.resolver.resolve(f'{sel}._domainkey.{domain}', 'TXT')
                    for rdata in answers:
                        txt = str(rdata)
                        if 'v=DKIM1' in txt or 'p=' in txt:
                            result['dkim']['status'] = 'valid'
                            result['dkim']['details'] = f'selector: {sel}'
                            result['score'] += 30
                            found = True
                            break
                    if found:
                        break
                except:
                    pass
            if not found:
                result['dkim']['status'] = 'not_found'
        except Exception as e:
            result['dkim']['status'] = 'error'
        
        # Определяем итоговый статус
        if result['score'] >= 70:
            result['status'] = 'good'
        elif result['score'] >= 40:
            result['status'] = 'warning'
        else:
            result['status'] = 'poor'
        
        self.domain_auth_cache[domain] = result
        return result
    
    def check_virustotal_domain(self, domain):
        """Проверка домена через VirusTotal"""
        if not self.vt_api_key or not self.online_mode or not REQUESTS_AVAILABLE:
            return {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'unknown'}
        
        if domain in self.domain_vt_cache:
            return self.domain_vt_cache[domain]
        
        try:
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                
                result = {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'score': 100 - min(100, (malicious + suspicious) * 10),
                    'status': 'clean' if malicious == 0 else 'malicious' if malicious > 5 else 'suspicious'
                }
            else:
                result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'unknown'}
        except Exception as e:
            result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'error'}
        
        self.domain_vt_cache[domain] = result
        return result
    
    def check_virustotal_ip(self, ip):
        """Проверка IP через VirusTotal"""
        if not self.vt_api_key or not self.online_mode or not REQUESTS_AVAILABLE:
            return {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'unknown', 'country': None, 'asn': None}
        
        if ip in self.ip_vt_cache:
            return self.ip_vt_cache[ip]
        
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                
                country = attributes.get('country', None)
                asn = attributes.get('as_owner', None)
                
                result = {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'score': 100 - min(100, (malicious + suspicious) * 10),
                    'status': 'clean' if malicious == 0 else 'malicious' if malicious > 5 else 'suspicious',
                    'country': country,
                    'asn': asn
                }
            else:
                result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'unknown', 'country': None, 'asn': None}
        except Exception as e:
            result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'error', 'country': None, 'asn': None}
        
        self.ip_vt_cache[ip] = result
        return result
    
    def update_compromised(self, obj_type, value, reason, severity):
        """Добавление в таблицу засвеченных объектов"""
        self.cursor.execute('''
            INSERT OR IGNORE INTO compromised (type, value, reason, severity, detected_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (obj_type, value, reason, severity, datetime.now().isoformat()))
        self.conn.commit()
    
    def update_attachment_hash(self, attachment):
        """Обновление информации о хеше вложения"""
        vt_result = self.check_virustotal_hash(attachment['sha256'])
        
        # Определяем статус
        if vt_result.get('malicious', 0) > 0:
            reputation_status = 'malicious'
            self.update_compromised('hash', attachment['sha256'], 
                                   f"VT malicious: {vt_result['malicious']} detections", 'high')
        elif vt_result.get('suspicious', 0) > 0:
            reputation_status = 'suspicious'
        else:
            reputation_status = 'clean'
        
        # Сохраняем в таблицу hashes
        self.cursor.execute('''
            INSERT INTO hashes (hash, hash_type, vt_malicious, vt_suspicious, vt_score,
                               reputation_status, file_type, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                vt_malicious = COALESCE(?, vt_malicious),
                vt_suspicious = COALESCE(?, vt_suspicious),
                vt_score = COALESCE(?, vt_score),
                reputation_status = ?,
                last_checked = ?
        ''', (
            attachment['sha256'], 'sha256',
            vt_result['malicious'], vt_result['suspicious'], vt_result['score'],
            reputation_status, attachment['content_type'], datetime.now().isoformat(),
            vt_result['malicious'], vt_result['suspicious'], vt_result['score'],
            reputation_status, datetime.now().isoformat()
        ))
        
        # Сохраняем в таблицу attachments
        self.cursor.execute('''
            INSERT INTO attachments (
                email_id, file_number, filename, content_type, size,
                md5, sha1, sha256, vt_malicious, vt_suspicious, vt_score,
                reputation_status, last_checked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            attachment['email_id'], attachment['file_number'], attachment['filename'],
            attachment['content_type'], attachment['size'], attachment['md5'],
            attachment['sha1'], attachment['sha256'], vt_result['malicious'],
            vt_result['suspicious'], vt_result['score'], reputation_status,
            datetime.now().isoformat()
        ))
        
        self.conn.commit()
    
    def extract_sender_info(self, from_header):
        """Извлечение информации об отправителе"""
        if not from_header:
            return (None, None, None)
        
        name, email_addr = parseaddr(from_header)
        
        if not name:
            name_match = re.search(r'^([^<]+)\s*<', from_header)
            if name_match:
                name = name_match.group(1).strip()
        
        if not name and email_addr:
            name = email_addr.split('@')[0]
        
        if name:
            name = name.strip(' "\'')
        
        domain = None
        if email_addr:
            domain_match = self.domain_pattern.search(email_addr)
            if domain_match:
                domain = domain_match.group(1).lower()
        
        return (name if name else None, email_addr if email_addr else None, domain)
    
    def find_next_files(self, start_num):
        """Интеллектуальный поиск следующих файлов"""
        found_files = []
        current = start_num
        
        while len(found_files) < 1 and current <= self.max_files:
            eml_file = self.eml_dir / f"{current}.eml"
            if eml_file.exists():
                found_files.append(current)
                self.log_scan(current, "FOUND", f"File {current}.eml found")
                break
            else:
                self.log_scan(current, "MISSING", f"File {current}.eml not found")
                self.missing_files.append(current)
                
                next_check = current + 1
                found_in_next = False
                
                for offset in range(1, self.skip_check + 1):
                    check_num = current + offset
                    if check_num > self.max_files:
                        break
                    
                    check_file = self.eml_dir / f"{check_num}.eml"
                    if check_file.exists():
                        found_files.append(check_num)
                        self.log_scan(check_num, "FOUND", 
                                     f"File {check_num}.eml found (skipped {offset} files)")
                        found_in_next = True
                        break
                    else:
                        self.log_scan(check_num, "MISSING", 
                                     f"File {check_num}.eml not found")
                        self.missing_files.append(check_num)
                
                if found_in_next:
                    return found_files
                else:
                    current += self.skip_check + 1
                    continue
        
        return found_files
    
    def extract_urls_from_email(self, msg, file_number, sender_email, subject):
        """Извлечение ссылок из письма с классификацией облачных хранилищ"""
        all_urls = set()
        cloud_urls = []
        
        body = self.extract_body(msg)
        if body:
            for match in self.url_pattern.finditer(body):
                url = match.group(0).rstrip('.,;:!?\'"')
                all_urls.add(url)
                
                # Проверяем, является ли ссылка файловым хранилищем
                storage_type = self.get_storage_type(url)
                if storage_type:
                    cloud_urls.append({
                        'url': url,
                        'storage_type': storage_type,
                        'file_number': file_number,
                        'sender_email': sender_email,
                        'subject': subject,
                        'detected_at': datetime.now().isoformat()
                    })
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        html_text = payload.decode(charset, errors='ignore')
                        html_urls = re.findall(r'href=["\'](https?://[^"\']+)["\']', html_text, re.IGNORECASE)
                        for url in html_urls:
                            all_urls.add(url)
                            
                            storage_type = self.get_storage_type(url)
                            if storage_type:
                                cloud_urls.append({
                                    'url': url,
                                    'storage_type': storage_type,
                                    'file_number': file_number,
                                    'sender_email': sender_email,
                                    'subject': subject,
                                    'detected_at': datetime.now().isoformat()
                                })
                    except:
                        pass
        
        # Сохраняем ссылки на хранилища в БД
        for cloud_url in cloud_urls:
            self.cursor.execute('''
                INSERT INTO cloud_storage_urls (url, storage_type, file_number, sender_email, subject, detected_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (cloud_url['url'], cloud_url['storage_type'], cloud_url['file_number'],
                  cloud_url['sender_email'], cloud_url['subject'], cloud_url['detected_at']))
        
        self.conn.commit()
        return all_urls, cloud_urls
    
    def scan_files(self):
        """Сканирование файлов"""
        print("🔍 Начинаю интеллектуальное сканирование файлов...")
        print(f"📁 Диапазон: 1 до {self.max_files}")
        print(f"🔎 Проверка следующих {self.skip_check} файлов при пропуске")
        if self.online_mode:
            print(f"🌐 Режим: ONLINE (VirusTotal + проверка аутентификации)")
        if self.extract_attachments:
            print(f"📎 Извлечение вложений: ВКЛЮЧЕНО")
        print("-" * 60)
        
        processed = 0
        current_num = 1
        total_found = 0
        
        while current_num <= self.max_files:
            next_files = self.find_next_files(current_num)
            
            if next_files:
                file_num = next_files[0]
                eml_file = self.eml_dir / f"{file_num}.eml"
                
                if self.process_eml_file(file_num, eml_file):
                    total_found += 1
                
                processed += 1
                current_num = file_num + 1
                
                if processed % 50 == 0:
                    print(f"  📊 Прогресс: проверено позиций до {current_num-1}, "
                          f"найдено файлов: {total_found}")
            else:
                print(f"  ℹ️ Достигнут предел {self.max_files}, новых файлов не найдено")
                break
        
        print("-" * 60)
        print(f"✅ Сканирование завершено!")
        print(f"  📁 Всего проверено позиций: {current_num-1}")
        print(f"  📧 Найдено EML файлов: {total_found}")
        print(f"  🔗 Найдено уникальных ссылок: {len(self.all_urls)}")
        print(f"  ☁️ Найдено ссылок на облачные хранилища: {len(self.cloud_storage_urls)}")
        print(f"  📎 Найдено вложений: {len(self.attachments_data)}")
        print(f"  ⚠️ Пропущено файлов: {len(self.missing_files)}")
        
        return total_found
    
    def process_eml_file(self, file_num, eml_file):
        """Обработка одного EML файла"""
        try:
            with open(eml_file, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            from_header = msg.get('From', '')
            subject = msg.get('Subject', '') or '(без темы)'
            message_date = msg.get('Date', '')
            
            sender_name, sender_email, sender_domain = self.extract_sender_info(from_header)
            
            if sender_domain:
                self.domain_counter[sender_domain] += 1
            
            ips = self.extract_ip_from_headers(msg)
            for ip in ips:
                self.ip_counter[ip] += 1
            
            has_attachment = self.check_attachments(msg)
            body = self.extract_body(msg)
            
            # Извлекаем ссылки с классификацией облачных хранилищ
            urls, cloud_urls = self.extract_urls_from_email(msg, file_num, sender_email, subject)
            urls_json = json.dumps(list(urls), ensure_ascii=False) if urls else None
            cloud_urls_json = json.dumps(cloud_urls, ensure_ascii=False) if cloud_urls else None
            
            for url in urls:
                self.all_urls.add(url)
                self.url_counter[url] += 1
            
            for cloud_url in cloud_urls:
                self.cloud_storage_urls.append(cloud_url)
            
            email_record = {
                'file_number': file_num,
                'filename': eml_file.name,
                'sender_name': sender_name,
                'sender_email': sender_email,
                'sender_domain': sender_domain,
                'sender_ips': ', '.join(ips) if ips else '',
                'subject': subject,
                'has_attachment': has_attachment,
                'body_text': body[:5000],
                'message_date': message_date,
                'extracted_urls': urls_json,
                'cloud_urls': cloud_urls_json,
                'count_ips': len(ips),
                'count_urls': len(urls),
                'count_cloud_urls': len(cloud_urls)
            }
            self.emails_data.append(email_record)
            
            self.cursor.execute('''
                INSERT INTO emails (
                    file_number, filename, sender_name, sender_email, sender_domain,
                    sender_ip, subject, has_attachment, body_text, message_date, 
                    extracted_urls, cloud_urls, file_exists
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_num, eml_file.name, sender_name, sender_email, sender_domain,
                email_record['sender_ips'], subject, has_attachment, body, message_date,
                urls_json, cloud_urls_json, 1
            ))
            
            email_id = self.cursor.lastrowid
            
            # Извлекаем вложения и их хеши
            if has_attachment and msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_disposition() == 'attachment':
                        attachment_info = self.extract_attachment_hashes(part, email_id, file_num)
                        if attachment_info:
                            self.attachments_data.append(attachment_info)
                            self.update_attachment_hash(attachment_info)
                            print(f"    📎 Вложение: {attachment_info['filename']} "
                                  f"(SHA256: {attachment_info['sha256'][:16]}...)")
            
            # Обновляем статистику домена
            if sender_domain:
                self.update_domain_stats(sender_domain, 1)
            
            # Обновляем статистику IP
            for ip in ips:
                self.update_ip_stats(ip, 1)
            
            # Обновляем таблицу отправителей
            if sender_email:
                auth_result = self.check_spf_dmarc_dkim(sender_domain) if sender_domain else {'status': 'unknown', 'score': 0}
                vt_result = self.check_virustotal_domain(sender_domain) if sender_domain and self.online_mode else {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'unknown'}
                
                self.cursor.execute('''
                    INSERT INTO senders (sender_email, sender_name, count, domain, 
                                         spf_status, dkim_status, dmarc_status, auth_score,
                                         vt_malicious, vt_suspicious, vt_score, reputation_status, last_checked)
                    VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sender_email) DO UPDATE SET
                        count = count + 1,
                        sender_name = COALESCE(?, sender_name),
                        vt_malicious = COALESCE(?, vt_malicious),
                        vt_suspicious = COALESCE(?, vt_suspicious),
                        vt_score = COALESCE(?, vt_score),
                        last_checked = ?
                ''', (
                    sender_email, sender_name, sender_domain,
                    auth_result['spf']['status'],
                    auth_result['dkim']['status'],
                    auth_result['dmarc']['status'],
                    auth_result['score'],
                    vt_result['malicious'],
                    vt_result['suspicious'],
                    vt_result['score'],
                    vt_result['status'],
                    datetime.now().isoformat(),
                    sender_name,
                    vt_result['malicious'],
                    vt_result['suspicious'],
                    vt_result['score'],
                    datetime.now().isoformat()
                ))
            
            # Сохраняем ссылки
            for url in urls:
                url_domain = None
                protocol = None
                if url.startswith('https://'):
                    protocol = 'https'
                    url_domain = url.replace('https://', '').split('/')[0]
                elif url.startswith('http://'):
                    protocol = 'http'
                    url_domain = url.replace('http://', '').split('/')[0]
                
                self.cursor.execute('''
                    INSERT INTO urls (url, domain, protocol, count, first_seen, last_seen)
                    VALUES (?, ?, ?, 1, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET 
                        count = count + 1,
                        last_seen = ?
                ''', (url, url_domain, protocol, message_date, message_date, message_date))
            
            self.conn.commit()
            
            if len(self.emails_data) % 100 == 0:
                print(f"  ✅ Обработано {len(self.emails_data)} файлов...")
            
            return True
            
        except Exception as e:
            print(f"  ⚠️ Ошибка при обработке {eml_file.name}: {e}")
            self.log_scan(file_num, "ERROR", str(e))
            return False
    
    def update_domain_stats(self, domain, count):
        """Обновление статистики домена"""
        auth_result = self.check_spf_dmarc_dkim(domain)
        
        if self.online_mode:
            vt_result = self.check_virustotal_domain(domain)
        else:
            vt_result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'unknown'}
        
        # Определяем общий статус репутации
        if auth_result['status'] == 'poor' or vt_result.get('malicious', 0) > 0:
            reputation_status = 'bad'
            self.update_compromised('domain', domain, 
                                   f"DKIM/DMARC/SPF: {auth_result['status']}, VT: {vt_result.get('status', 'unknown')}",
                                   'high' if vt_result.get('malicious', 0) > 0 else 'medium')
        elif auth_result['status'] == 'warning' or vt_result.get('suspicious', 0) > 0:
            reputation_status = 'warning'
        else:
            reputation_status = 'good'
        
        self.cursor.execute('''
            INSERT INTO domains (domain, count, spf_status, dkim_status, dmarc_status, 
                                 auth_score, vt_malicious, vt_suspicious, vt_score, 
                                 reputation_status, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                count = count + ?,
                spf_status = COALESCE(?, spf_status),
                dkim_status = COALESCE(?, dkim_status),
                dmarc_status = COALESCE(?, dmarc_status),
                auth_score = COALESCE(?, auth_score),
                vt_malicious = COALESCE(?, vt_malicious),
                vt_suspicious = COALESCE(?, vt_suspicious),
                vt_score = COALESCE(?, vt_score),
                reputation_status = ?,
                last_checked = ?
        ''', (
            domain, count,
            auth_result['spf']['status'],
            auth_result['dkim']['status'],
            auth_result['dmarc']['status'],
            auth_result['score'],
            vt_result['malicious'],
            vt_result['suspicious'],
            vt_result['score'],
            reputation_status,
            datetime.now().isoformat(),
            count,
            auth_result['spf']['status'],
            auth_result['dkim']['status'],
            auth_result['dmarc']['status'],
            auth_result['score'],
            vt_result['malicious'],
            vt_result['suspicious'],
            vt_result['score'],
            reputation_status,
            datetime.now().isoformat()
        ))
        self.conn.commit()
    
    def update_ip_stats(self, ip, count):
        """Обновление статистики IP"""
        vt_result = {'malicious': 0, 'suspicious': 0, 'score': 0, 'status': 'unknown', 'country': None, 'asn': None}
        
        if self.online_mode and ip and ip != '' and REQUESTS_AVAILABLE:
            vt_result = self.check_virustotal_ip(ip)
        
        # Определяем статус
        if vt_result.get('malicious', 0) > 0:
            reputation_status = 'bad'
            self.update_compromised('ip', ip, f"VT malicious: {vt_result['malicious']}", 'high')
        elif vt_result.get('suspicious', 0) > 0:
            reputation_status = 'warning'
        else:
            reputation_status = 'good'
        
        self.cursor.execute('''
            INSERT INTO ip_addresses (ip, count, vt_malicious, vt_suspicious, vt_score,
                                      reputation_status, country, asn, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                count = count + ?,
                vt_malicious = COALESCE(?, vt_malicious),
                vt_suspicious = COALESCE(?, vt_suspicious),
                vt_score = COALESCE(?, vt_score),
                reputation_status = ?,
                country = COALESCE(?, country),
                asn = COALESCE(?, asn),
                last_checked = ?
        ''', (
            ip, count,
            vt_result['malicious'],
            vt_result['suspicious'],
            vt_result['score'],
            reputation_status,
            vt_result.get('country'),
            vt_result.get('asn'),
            datetime.now().isoformat(),
            count,
            vt_result['malicious'],
            vt_result['suspicious'],
            vt_result['score'],
            reputation_status,
            vt_result.get('country'),
            vt_result.get('asn'),
            datetime.now().isoformat()
        ))
        self.conn.commit()
    
    def log_scan(self, file_num, status, message):
        """Логирование сканирования"""
        self.cursor.execute('''
            INSERT INTO scan_log (scan_time, file_number, status, message)
            VALUES (?, ?, ?, ?)
        ''', (datetime.now().isoformat(), file_num, status, message[:500]))
        self.conn.commit()
    
    def extract_ip_from_headers(self, msg):
        """Извлечение IP из заголовков письма"""
        ips = set()
        
        headers_to_check = ['Received', 'X-Originating-IP', 'X-Real-IP', 
                           'X-Forwarded-For', 'X-Sender-IP', 'X-Remote-IP']
        
        for header in headers_to_check:
            if header in msg:
                value = msg[header]
                if value:
                    found_ips = self.ip_pattern.findall(value)
                    for ip in found_ips:
                        octets = ip.split('.')
                        if all(0 <= int(o) <= 255 for o in octets):
                            ips.add(ip)
        
        return ips
    
    def check_attachments(self, msg):
        """Проверка наличия вложений"""
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = part.get("Content-Disposition", "")
                if content_disposition and "attachment" in content_disposition:
                    return 1
        return 0
    
    def extract_body(self, msg):
        """Извлечение текста письма"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        body += payload.decode(charset, errors='ignore')
                    except:
                        pass
                elif content_type == "text/html" and not body:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        html_text = payload.decode(charset, errors='ignore')
                        body += re.sub(r'<[^>]+>', ' ', html_text)
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors='ignore')
            except:
                body = str(msg.get_payload())
        
        body = re.sub(r'\s+', ' ', body)
        return body.strip()
    
    def generate_csv_reports(self):
        """Генерация всех CSV отчетов"""
        print("\n📊 Генерация CSV отчетов...")
        
        self.generate_domains_csv()
        self.generate_ips_csv()
        self.generate_compromised_csv()
        self.generate_senders_csv()
        self.generate_urls_csv()
        self.generate_attachments_csv()
        self.generate_hashes_csv()
        self.generate_cloud_storage_csv()
        
        print("✅ Все отчеты сгенерированы")
    
    def generate_cloud_storage_csv(self):
        """Генерация CSV со ссылками на облачные хранилища"""
        output_file = self.output_dir / "cloud_storage_links.csv"
        
        self.cursor.execute("""
            SELECT file_number, sender_email, subject, storage_type, url, detected_at
            FROM cloud_storage_urls 
            ORDER BY detected_at DESC
        """)
        data = self.cursor.fetchall()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['File_Number', 'Sender_Email', 'Subject', 'Storage_Type', 'URL', 'Detected_At'])
            writer.writerows(data)
        
        print(f"  📄 {output_file.name} - {len(data)} ссылок на облачные хранилища")
    
    def generate_attachments_csv(self):
        """Генерация CSV с вложениями"""
        output_file = self.output_dir / "attachments.csv"
        
        self.cursor.execute("""
            SELECT file_number, filename, content_type, size, md5, sha1, sha256,
                   vt_malicious, vt_suspicious, vt_score, reputation_status
            FROM attachments 
            ORDER BY vt_malicious DESC, file_number
        """)
        data = self.cursor.fetchall()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['File_Number', 'Filename', 'Content_Type', 'Size_Bytes', 
                           'MD5', 'SHA1', 'SHA256', 'VT_Malicious', 'VT_Suspicious', 
                           'VT_Score', 'Reputation'])
            writer.writerows(data)
        
        print(f"  📄 {output_file.name} - {len(data)} вложений")
    
    def generate_hashes_csv(self):
        """Генерация CSV с хешами"""
        output_file = self.output_dir / "hashes.csv"
        
        self.cursor.execute("""
            SELECT hash, vt_malicious, vt_suspicious, vt_score, reputation_status, file_type
            FROM hashes 
            ORDER BY vt_malicious DESC
        """)
        data = self.cursor.fetchall()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Hash', 'VT_Malicious', 'VT_Suspicious', 'VT_Score', 'Reputation', 'File_Type'])
            writer.writerows(data)
        
        print(f"  📄 {output_file.name} - {len(data)} уникальных хешей")
    
    def generate_domains_csv(self):
        """Генерация CSV с доменами"""
        output_file = self.output_dir / "domains_with_reputation.csv"
        
        self.cursor.execute("""
            SELECT domain, count, spf_status, dkim_status, dmarc_status, 
                   auth_score, vt_malicious, vt_suspicious, vt_score, reputation_status
            FROM domains 
            ORDER BY count DESC
        """)
        data = self.cursor.fetchall()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Domain', 'Count', 'SPF', 'DKIM', 'DMARC', 'Auth_Score', 
                           'VT_Malicious', 'VT_Suspicious', 'VT_Score', 'Reputation'])
            writer.writerows(data)
        
        print(f"  📄 {output_file.name} - {len(data)} доменов")
    
    def generate_ips_csv(self):
        """Генерация CSV с IP"""
        output_file = self.output_dir / "ips_with_reputation.csv"
        
        self.cursor.execute("""
            SELECT ip, count, vt_malicious, vt_suspicious, vt_score, 
                   reputation_status, country, asn
            FROM ip_addresses 
            ORDER BY count DESC
        """)
        data = self.cursor.fetchall()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Count', 'VT_Malicious', 'VT_Suspicious', 'VT_Score', 
                           'Reputation', 'Country', 'ASN'])
            writer.writerows(data)
        
        print(f"  📄 {output_file.name} - {len(data)} IP адресов")
    
    def generate_compromised_csv(self):
        """Генерация CSV с засвеченными объектами"""
        output_file = self.output_dir / "compromised_indicators.csv"
        
        self.cursor.execute("""
            SELECT type, value, reason, severity, detected_at
            FROM compromised 
            ORDER BY severity DESC, detected_at DESC
        """)
        data = self.cursor.fetchall()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Value', 'Reason', 'Severity', 'Detected_At'])
            writer.writerows(data)
        
        print(f"  📄 {output_file.name} - {len(data)} засвеченных индикаторов")
    
    def generate_senders_csv(self):
        """Генерация CSV с отправителями"""
        output_file = self.output_dir / "senders_with_reputation.csv"
        
        self.cursor.execute("""
            SELECT sender_email, sender_name, count, domain, 
                   spf_status, dkim_status, dmarc_status, auth_score,
                   vt_malicious, vt_suspicious, vt_score, reputation_status
            FROM senders 
            ORDER BY count DESC
        """)
        data = self.cursor.fetchall()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Email', 'Name', 'Count', 'Domain', 'SPF', 'DKIM', 'DMARC', 
                           'Auth_Score', 'VT_Malicious', 'VT_Suspicious', 'VT_Score', 'Reputation'])
            writer.writerows(data)
        
        print(f"  📄 {output_file.name} - {len(data)} отправителей")
    
    def generate_urls_csv(self):
        """Генерация CSV с ссылками"""
        output_file = self.output_dir / "urls.csv"
        
        self.cursor.execute("""
            SELECT url, domain, protocol, count, first_seen, last_seen
            FROM urls 
            ORDER BY count DESC
        """)
        data = self.cursor.fetchall()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Domain', 'Protocol', 'Count', 'First_Seen', 'Last_Seen'])
            writer.writerows(data)
        
        print(f"  📄 {output_file.name} - {len(data)} уникальных ссылок")
    
    def generate_html_report(self):
        """Генерация HTML отчета с разделением по категориям угроз"""
        output_file = self.output_dir / "report.html"
        
        # Получаем вредоносные вложения с информацией об отправителе
        self.cursor.execute("""
            SELECT 
                a.filename, 
                a.sha256, 
                a.vt_malicious, 
                a.reputation_status,
                e.sender_email,
                e.subject,
                e.sender_ip,
                e.sender_domain,
                e.file_number
            FROM attachments a
            JOIN emails e ON a.file_number = e.file_number
            WHERE a.vt_malicious > 0 OR a.reputation_status = 'malicious'
            ORDER BY a.vt_malicious DESC
        """)
        malicious_attachments = self.cursor.fetchall()
        
        # Получаем вредоносные IP адреса
        self.cursor.execute("""
            SELECT ip, count, vt_malicious, reputation_status, country
            FROM ip_addresses 
            WHERE vt_malicious > 0 OR reputation_status = 'bad'
            ORDER BY vt_malicious DESC
        """)
        malicious_ips = self.cursor.fetchall()
        
        # Получаем отправителей с плохой репутацией
        self.cursor.execute("""
            SELECT 
                sender_email, 
                count, 
                vt_malicious, 
                reputation_status,
                domain
            FROM senders 
            WHERE vt_malicious > 0 OR reputation_status = 'bad'
            ORDER BY vt_malicious DESC
        """)
        malicious_senders = self.cursor.fetchall()
        
        # Получаем домены с плохой репутацией
        self.cursor.execute("""
            SELECT domain, count, vt_malicious, reputation_status
            FROM domains 
            WHERE vt_malicious > 0 OR reputation_status = 'bad'
            ORDER BY vt_malicious DESC
        """)
        malicious_domains = self.cursor.fetchall()
        
        # Получаем вредоносные ссылки (для примера - ссылки с подозрительных доменов)
        self.cursor.execute("""
            SELECT url, domain, count
            FROM urls 
            WHERE domain IN (SELECT domain FROM domains WHERE vt_malicious > 0)
            ORDER BY count DESC
            LIMIT 50
        """)
        malicious_urls = self.cursor.fetchall()
        
        # Получаем ссылки на облачные хранилища
        self.cursor.execute("""
            SELECT file_number, sender_email, subject, storage_type, url
            FROM cloud_storage_urls 
            ORDER BY detected_at DESC
        """)
        cloud_urls = self.cursor.fetchall()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Security Analysis Report - Threat Assessment</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1e1e2e; color: #cdd6f4; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #313244; padding: 20px; border-radius: 12px; }}
        h1 {{ color: #89b4fa; border-bottom: 3px solid #89b4fa; padding-bottom: 10px; }}
        h2 {{ color: #a6e3a1; margin-top: 30px; border-left: 4px solid #a6e3a1; padding-left: 15px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; font-size: 13px; }}
        th, td {{ border: 1px solid #45475a; padding: 8px; text-align: left; }}
        th {{ background-color: #45475a; color: #cdd6f4; font-weight: bold; }}
        tr:nth-child(even) {{ background-color: #313244; }}
        tr:hover {{ background-color: #45475a; }}
        .stats {{ display: inline-block; margin: 10px; padding: 15px; background: #1e1e2e; border-radius: 8px; min-width: 150px; }}
        .number {{ font-size: 28px; font-weight: bold; }}
        .critical {{ color: #f38ba8; }}
        .warning {{ color: #fab387; }}
        .good {{ color: #a6e3a1; }}
        .footer {{ margin-top: 30px; padding-top: 10px; border-top: 1px solid #45475a; font-size: 12px; color: #6c7086; text-align: center; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
        .badge-high {{ background-color: #f38ba8; color: #1e1e2e; }}
        .hash {{ font-family: monospace; font-size: 11px; }}
        .url {{ word-break: break-all; }}
    </style>
</head>
<body>
<div class="container">
    <h1>📧 Email Security Analysis Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <!-- Threat Summary Cards -->
    <div class="stats"><div class="number critical">{len(malicious_senders)}</div><div>🚨 Отправителей с угрозами</div></div>
    <div class="stats"><div class="number critical">{len(malicious_attachments)}</div><div>📎 Вредоносных вложений</div></div>
    <div class="stats"><div class="number critical">{len(malicious_ips)}</div><div>🌐 Вредоносных IP</div></div>
    <div class="stats"><div class="number warning">{len(malicious_domains)}</div><div>⚠️ Подозрительных доменов</div></div>
    <div class="stats"><div class="number">{len(cloud_urls)}</div><div>☁️ Ссылок на облачные хранилища</div></div>
    
    <!-- 1. Вредоносные вложения (хеши) -->
    <h2>📎 ВРЕДОНОСНЫЕ ВЛОЖЕНИЯ (ХЕШИ)</h2>
    <table>
        <thead><tr><th>Отправитель</th><th>Тема письма</th><th>IP адрес</th><th>Домен</th><th>Хеш (SHA256)</th><th>Ссылка</th></tr></thead>
        <tbody>
""")
            if malicious_attachments:
                for attach in malicious_attachments:
                    filename, sha256, vt_mal, rep, sender_email, subject, sender_ip, sender_domain, file_num = attach
                    f.write(f"""<tr>
                        <td>{sender_email or '—'}</td>
                        <td>{subject[:50] if subject else '—'}</td>
                        <td>{sender_ip or '—'}</td>
                        <td>{sender_domain or '—'}</td>
                        <td class="hash" title="{sha256}">{sha256[:32]}...</td>
                        <td>—</td>
                    </tr>\n""")
            else:
                f.write('<tr><td colspan="6" class="good">✅ Вредоносных вложений не обнаружено</td></tr>\n')
            f.write("</tbody></table>\n")
            
            # 2. Вредоносные IP адреса
            f.write("""
    <h2>🌐 ВРЕДОНОСНЫЕ IP АДРЕСА</h2>
    <table>
        <thead><tr><th>Отправитель</th><th>Тема письма</th><th>IP адрес</th><th>Домен</th><th>Хеш</th><th>Ссылка</th></tr></thead>
        <tbody>
""")
            if malicious_ips:
                # Для IP нужно получить связанные письма
                for ip_data in malicious_ips[:50]:
                    ip_addr, count, vt_mal, rep, country = ip_data
                    # Находим письма с этого IP
                    self.cursor.execute("""
                        SELECT sender_email, subject, sender_domain, file_number 
                        FROM emails WHERE sender_ip LIKE ? LIMIT 3
                    """, (f"%{ip_addr}%",))
                    emails_from_ip = self.cursor.fetchall()
                    for email_ip in emails_from_ip:
                        sender_email, subject, sender_domain, file_num = email_ip
                        f.write(f"""<tr>
                            <td>{sender_email or '—'}</td>
                            <td>{subject[:50] if subject else '—'}</td>
                            <td class="critical">{ip_addr}</td>
                            <td>{sender_domain or '—'}</td>
                            <td>—</td>
                            <td>—</td>
                        </tr>\n""")
            else:
                f.write('<tr><td colspan="6" class="good">✅ Вредоносных IP не обнаружено</td></tr>\n')
            f.write("</tbody></table>\n")
            
            # 3. Отправители с угрозами
            f.write("""
    <h2>👤 ОТПРАВИТЕЛИ С УГРОЗАМИ</h2>
    <table>
        <thead><tr><th>Отправитель</th><th>Тема письма</th><th>IP адрес</th><th>Домен</th><th>Хеш</th><th>Ссылка</th></tr></thead>
        <tbody>
""")
            if malicious_senders:
                for sender in malicious_senders:
                    sender_email, count, vt_mal, rep, domain = sender
                    # Находим письма от этого отправителя
                    self.cursor.execute("""
                        SELECT subject, sender_ip, file_number 
                        FROM emails WHERE sender_email = ? LIMIT 3
                    """, (sender_email,))
                    emails_from_sender = self.cursor.fetchall()
                    for email_sender in emails_from_sender:
                        subject, sender_ip, file_num = email_sender
                        f.write(f"""<tr>
                            <td class="critical">{sender_email}</td>
                            <td>{subject[:50] if subject else '—'}</td>
                            <td>{sender_ip or '—'}</td>
                            <td>{domain or '—'}</td>
                            <td>—</td>
                            <td>—</td>
                        </tr>\n""")
            else:
                f.write('<tr><td colspan="6" class="good">✅ Отправителей с угрозами не обнаружено</td></tr>\n')
            f.write("</tbody></table>\n")
            
            # 4. Подозрительные домены
            f.write("""
    <h2>⚠️ ПОДОЗРИТЕЛЬНЫЕ ДОМЕНЫ</h2>
    <table>
        <thead><tr><th>Отправитель</th><th>Тема письма</th><th>IP адрес</th><th>Домен</th><th>Хеш</th><th>Ссылка</th></tr></thead>
        <tbody>
""")
            if malicious_domains:
                for domain_data in malicious_domains:
                    domain, count, vt_mal, rep = domain_data
                    # Находим письма с этого домена
                    self.cursor.execute("""
                        SELECT sender_email, subject, sender_ip, file_number 
                        FROM emails WHERE sender_domain = ? LIMIT 3
                    """, (domain,))
                    emails_from_domain = self.cursor.fetchall()
                    for email_domain in emails_from_domain:
                        sender_email, subject, sender_ip, file_num = email_domain
                        f.write(f"""<tr>
                            <td>{sender_email or '—'}</td>
                            <td>{subject[:50] if subject else '—'}</td>
                            <td>{sender_ip or '—'}</td>
                            <td class="warning">{domain}</td>
                            <td>—</td>
                            <td>—</td>
                        </tr>\n""")
            else:
                f.write('<tr><td colspan="6" class="good">✅ Подозрительных доменов не обнаружено</td></tr>\n')
            f.write("</tbody></table>\n")
            
            # 5. Вредоносные ссылки
            f.write("""
    <h2>🔗 ВРЕДОНОСНЫЕ ССЫЛКИ</h2>
    <table>
        <thead><tr><th>Отправитель</th><th>Тема письма</th><th>IP адрес</th><th>Домен</th><th>Хеш</th><th>Ссылка</th></tr></thead>
        <tbody>
""")
            if malicious_urls:
                for url_data in malicious_urls[:50]:
                    url, domain, count = url_data
                    # Находим письма с этой ссылкой
                    self.cursor.execute("""
                        SELECT sender_email, subject, sender_ip, sender_domain, file_number 
                        FROM emails WHERE extracted_urls LIKE ? LIMIT 3
                    """, (f"%{url}%",))
                    emails_with_url = self.cursor.fetchall()
                    for email_url in emails_with_url:
                        sender_email, subject, sender_ip, sender_domain, file_num = email_url
                        f.write(f"""<tr>
                            <td>{sender_email or '—'}</td>
                            <td>{subject[:50] if subject else '—'}</td>
                            <td>{sender_ip or '—'}</td>
                            <td>{sender_domain or '—'}</td>
                            <td>—</td>
                            <td class="url">{url[:80]}...</td>
                        </tr>\n""")
            else:
                f.write('<tr><td colspan="6" class="good">✅ Вредоносных ссылок не обнаружено</td></tr>\n')
            f.write("</tbody></table>\n")
            
            # 6. Ссылки на облачные хранилища
            f.write("""
    <h2>☁️ ССЫЛКИ НА ОБЛАЧНЫЕ ХРАНИЛИЩА</h2>
    <table>
        <thead><tr><th>Отправитель</th><th>Тема письма</th><th>IP адрес</th><th>Домен</th><th>Хеш</th><th>Ссылка</th></tr></thead>
        <tbody>
""")
            if cloud_urls:
                for cloud in cloud_urls[:100]:
                    file_num, sender_email, subject, storage_type, url = cloud
                    # Получаем IP и домен для этого письма
                    self.cursor.execute("""
                        SELECT sender_ip, sender_domain FROM emails WHERE file_number = ?
                    """, (file_num,))
                    ip_domain = self.cursor.fetchone()
                    sender_ip = ip_domain[0] if ip_domain else '—'
                    sender_domain = ip_domain[1] if ip_domain else '—'
                    f.write(f"""<tr>
                        <td>{sender_email or '—'}</td>
                        <td>{subject[:50] if subject else '—'}</td>
                        <td>{sender_ip}</td>
                        <td>{sender_domain}</td>
                        <td>—</td>
                        <td class="url"><span class="badge badge-medium">{storage_type}</span> {url[:80]}...</td>
                    </tr>\n""")
            else:
                f.write('<tr><td colspan="6" class="good">✅ Ссылок на облачные хранилища не обнаружено</td></tr>\n')
            f.write("</tbody></table>\n")
            
            f.write(f"""
    <div class="footer">
        <p>Generated by Email Analyzer Advanced v3.0 | Threat Assessment Report</p>
        <p>Total messages analyzed: {len(self.emails_data)} | Attachments: {len(self.attachments_data)} | Cloud storage links: {len(cloud_urls)}</p>
    </div>
</div>
</body>
</html>
""")
        
        print(f"  🌐 {output_file.name} - HTML отчет с анализом угроз создан")
    
    def run(self):
        """Запуск всего анализа"""
        print("=" * 70)
        print("📧 Email Analyzer Advanced v3.0 (with Cloud Storage Detection)")
        print("=" * 70)
        
        total_files = self.scan_files()
        
        if total_files == 0:
            print("❌ Нет файлов для анализа!")
            return
        
        self.generate_csv_reports()
        self.generate_html_report()
        
        print("\n" + "=" * 70)
        print(f"✅ Анализ завершен! Результаты в: {self.output_dir}")
        print("=" * 70)
        
        # Финальная статистика
        self.cursor.execute("SELECT COUNT(*) FROM compromised")
        compromised_count = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM domains WHERE reputation_status = 'bad'")
        bad_domains = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM ip_addresses WHERE reputation_status = 'bad'")
        bad_ips = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM attachments WHERE vt_malicious > 0")
        malicious_attachments = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM cloud_storage_urls")
        cloud_count = self.cursor.fetchone()[0]
        
        print(f"\n📈 Итоговая статистика:")
        print(f"  📧 Обработано сообщений: {len(self.emails_data)}")
        print(f"  🌐 Уникальных доменов: {len(self.domain_counter)}")
        print(f"  🖧 Уникальных IP: {len(self.ip_counter)}")
        print(f"  🔗 Уникальных ссылок: {len(self.all_urls)}")
        print(f"  ☁️ Ссылок на облачные хранилища: {cloud_count}")
        print(f"  📎 Извлечено вложений: {len(self.attachments_data)}")
        print(f"  🦠 Вредоносных вложений: {malicious_attachments}")
        print(f"  🚨 Засвеченных индикаторов: {compromised_count}")
        print(f"  ⚠️ Доменов с плохой репутацией: {bad_domains}")
        print(f"  ⚠️ IP с плохой репутацией: {bad_ips}")
        
        if self.extract_attachments:
            print(f"  💾 Вложения сохранены в: {self.attachments_dir}")
        
        self.conn.close()


def main():
    if len(sys.argv) < 2:
        print("Использование: python3 email_analyzer_advanced.py <директория_с_eml> [опции]")
        print("\nОбязательные параметры:")
        print("  директория_с_eml     - папка с EML файлами")
        print("\nОпции:")
        print("  -o, --output DIR     - выходная директория (по умолчанию ./email_analysis_results)")
        print("  -m, --max NUM        - максимальный номер файла (по умолчанию 10000)")
        print("  -s, --skip NUM       - сколько следующих файлов проверять при пропуске (по умолчанию 5)")
        print("  --online             - включить онлайн-проверки (VirusTotal, SPF/DKIM/DMARC)")
        print("  --vt-api-key KEY     - API ключ VirusTotal (обязателен для онлайн-режима)")
        print("  --extract-attachments- извлечь вложения на диск")
        print("\nПримеры:")
        print("  # Офлайн-режим (только локальный анализ)")
        print("  python3 email_analyzer_advanced.py /home/kali/Downloads/ -o ./results")
        print("\n  # Онлайн-режим с проверкой репутации и извлечением вложений")
        print("  python3 email_analyzer_advanced.py /home/kali/Downloads/ --online --vt-api-key YOUR_KEY --extract-attachments")
        sys.exit(1)
    
    eml_dir = sys.argv[1]
    output_dir = "./email_analysis_results"
    max_files = 10000
    skip_check = 5
    online_mode = False
    vt_api_key = None
    extract_attachments = False
    
    # Парсим аргументы
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ['-o', '--output'] and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
            i += 2
        elif arg in ['-m', '--max'] and i + 1 < len(sys.argv):
            max_files = int(sys.argv[i + 1])
            i += 2
        elif arg in ['-s', '--skip'] and i + 1 < len(sys.argv):
            skip_check = int(sys.argv[i + 1])
            i += 2
        elif arg == '--online':
            online_mode = True
            i += 1
        elif arg == '--vt-api-key' and i + 1 < len(sys.argv):
            vt_api_key = sys.argv[i + 1]
            i += 2
        elif arg == '--extract-attachments':
            extract_attachments = True
            i += 1
        else:
            i += 1
    
    if online_mode and not vt_api_key:
        print("⚠️ Внимание: Для онлайн-режима требуется API ключ VirusTotal")
        print("Получите ключ на https://www.virustotal.com/ и укажите --vt-api-key YOUR_KEY")
        response = input("Продолжить без VirusTotal? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
        online_mode = False
    
    analyzer = EmailAnalyzerAdvanced(eml_dir, output_dir, max_files, skip_check, vt_api_key, online_mode, extract_attachments)
    analyzer.run()


if __name__ == "__main__":
    main()
