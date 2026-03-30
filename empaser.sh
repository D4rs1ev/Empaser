#!/bin/bash
# empaser.sh - Email Parser (Empaser)
# Единый скрипт для установки, анализа и просмотра email сообщений
# Версия: 1.0
# Автор: Email Analysis Suite

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Глобальные переменные
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
ACTIVATE_SCRIPT="$VENV_DIR/bin/activate"
CONFIG_DIR="$SCRIPT_DIR/config"
VT_CONFIG="$CONFIG_DIR/vt_config.sh"
RESULTS_BASE_DIR="$SCRIPT_DIR/results"
CURRENT_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Функция для вывода заголовка
print_header() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                               ║${NC}"
    echo -e "${CYAN}║                         ${MAGENTA}📧 EMAIL PARSER (Empaser)${NC}                              ║${NC}"
    echo -e "${CYAN}║                     ${GREEN}Email Analysis Suite - Универсальный инструмент${NC}               ║${NC}"
    echo -e "${CYAN}║                                                                               ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Функция для вывода сообщений
print_info() { echo -e "${BLUE}ℹ️ $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️ $1${NC}"; }
print_step() { echo -e "${CYAN}▶ $1${NC}"; }

# Функция для проверки успешности
check_success() {
    if [ $? -eq 0 ]; then
        print_success "$1"
        return 0
    else
        print_error "$1"
        return 1
    fi
}

# Функция для создания директории с таймстемпом
create_timestamp_dir() {
    local base_dir="$1"
    local prefix="$2"
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local new_dir="${base_dir}/${prefix}_${timestamp}"
    mkdir -p "$new_dir"
    echo "$new_dir"
}

# Функция для проверки установки
check_installation() {
    print_step "Проверка наличия виртуального окружения..."
    
    if [ ! -d "$VENV_DIR" ]; then
        print_warning "Виртуальное окружение не найдено"
        return 1
    fi
    
    if [ ! -f "$ACTIVATE_SCRIPT" ]; then
        print_warning "Файл активации виртуального окружения не найден"
        return 1
    fi
    
    print_success "Виртуальное окружение найдено"
    return 0
}

# Функция для установки зависимостей
install_dependencies() {
    print_header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                         📦 УСТАНОВКА ЗАВИСИМОСТЕЙ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Обновление системы
    print_step "Обновление списка пакетов..."
    sudo apt update -qq 2>/dev/null
    check_success "Список пакетов обновлен"
    
    # Установка системных пакетов
    print_step "Установка системных пакетов..."
    sudo apt install -y -qq python3 python3-pip python3-venv python3-dev sqlite3 sqlitebrowser libmagic1 file unzip p7zip-full wget curl git build-essential libssl-dev libffi-dev dnsutils 2>/dev/null
    check_success "Системные пакеты установлены"
    
    # Создание виртуального окружения
    print_step "Создание виртуального окружения..."
    if [ -d "$VENV_DIR" ]; then
        rm -rf "$VENV_DIR"
    fi
    python3 -m venv "$VENV_DIR"
    check_success "Виртуальное окружение создано"
    
    # Активация и установка пакетов
    print_step "Активация виртуального окружения..."
    source "$ACTIVATE_SCRIPT"
    
    print_step "Обновление pip..."
    pip install --upgrade pip -q 2>/dev/null
    
    print_step "Установка Python пакетов (может занять несколько минут)..."
    
    PACKAGES=(
        "requests" "urllib3" "beautifulsoup4" "lxml" "python-magic"
        "chardet" "email-validator" "pandas" "numpy" "dkimpy"
        "dnspython" "checkdmarc" "spf-engine" "authheaders"
        "publicsuffix2" "sqlalchemy" "openpyxl" "tqdm" "colorama"
        "python-dateutil" "pytz"
    )
    
    for pkg in "${PACKAGES[@]}"; do
        echo -ne "\r   Установка $pkg...      "
        pip install "$pkg" -q 2>/dev/null
    done
    echo -e "\r${GREEN}   ✅ Все пакеты установлены${NC}"
    
    print_success "Установка завершена!"
    
    # Создание скриптов-оберток
    create_wrapper_scripts
    
    echo ""
    read -p "Нажмите Enter для продолжения..."
}

# Функция для создания скриптов-оберток
create_wrapper_scripts() {
    print_step "Создание скриптов-оберток..."
    
    cat > "$SCRIPT_DIR/run_analyzer.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/email_analyzer_advanced.py" "$@"
EOF
    chmod +x "$SCRIPT_DIR/run_analyzer.sh"
    
    cat > "$SCRIPT_DIR/run_viewer.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/email_viewer.py" "$@"
EOF
    chmod +x "$SCRIPT_DIR/run_viewer.sh"
    
    print_success "Скрипты-обертки созданы"
}

# Функция для настройки API ключа
setup_api_key() {
    print_header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                         🔑 НАСТРОЙКА API КЛЮЧА${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    print_info "API ключ VirusTotal необходим для проверки репутации доменов, IP и хешей"
    print_info "Получить ключ можно на: https://www.virustotal.com/gui/join-us"
    echo ""
    
    read -p "Введите API ключ VirusTotal (или Enter для пропуска): " VT_API_KEY
    
    if [ ! -z "$VT_API_KEY" ]; then
        mkdir -p "$CONFIG_DIR"
        echo "VT_API_KEY=$VT_API_KEY" > "$VT_CONFIG"
        chmod 600 "$VT_CONFIG"
        print_success "API ключ сохранен"
        
        cat > "$SCRIPT_DIR/load_config.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config/vt_config.sh"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    export VT_API_KEY
    echo "✅ Конфигурация загружена"
fi
EOF
        chmod +x "$SCRIPT_DIR/load_config.sh"
    else
        print_warning "API ключ не введен, онлайн-проверки будут недоступны"
    fi
    
    echo ""
    read -p "Нажмите Enter для продолжения..."
}

# Функция для анализа писем
run_analysis() {
    print_header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                         📧 АНАЛИЗ ПИСЕМ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Проверка наличия анализатора
    if [ ! -f "$SCRIPT_DIR/email_analyzer_advanced.py" ]; then
        print_error "Файл email_analyzer_advanced.py не найден!"
        read -p "Нажмите Enter для продолжения..."
        return 1
    fi
    
    # Ввод пути к EML файлам
    print_info "Укажите путь к директории с EML файлами"
    print_info "Файлы должны быть именованы как: 1.eml, 2.eml, 3.eml, ..."
    echo ""
    read -p "📁 Путь к EML файлам: " EML_PATH
    
    if [ ! -d "$EML_PATH" ]; then
        print_error "Директория не найдена: $EML_PATH"
        read -p "Нажмите Enter для продолжения..."
        return 1
    fi
    
    # Подсчет EML файлов
    EML_COUNT=$(find "$EML_PATH" -maxdepth 1 -name "*.eml" 2>/dev/null | wc -l)
    print_info "Найдено EML файлов: $EML_COUNT"
    
    # Создание директории для результатов с таймстемпом
    RESULT_DIR=$(create_timestamp_dir "$RESULTS_BASE_DIR" "analysis")
    print_success "Создана директория для результатов: $RESULT_DIR"
    
    # Выбор режима
    echo ""
    echo -e "${YELLOW}Выберите режим анализа:${NC}"
    echo "  [1] Быстрый анализ (только локальный, без проверок)"
    echo "  [2] Полный анализ (с проверкой репутации, требуется API ключ)"
    echo "  [3] Полный анализ + извлечение вложений"
    echo ""
    read -p "Ваш выбор (1-3): " ANALYSIS_MODE
    
    # Загрузка API ключа если есть
    if [ -f "$SCRIPT_DIR/load_config.sh" ]; then
        source "$SCRIPT_DIR/load_config.sh" 2>/dev/null
    fi
    
    # Формирование команды
    CMD="$SCRIPT_DIR/run_analyzer.sh \"$EML_PATH\" -o \"$RESULT_DIR\""
    
    case $ANALYSIS_MODE in
        2)
            if [ ! -z "$VT_API_KEY" ]; then
                CMD="$CMD --online --vt-api-key $VT_API_KEY"
                print_info "Режим: Полный анализ с проверкой репутации"
            else
                print_warning "API ключ не найден, выполняется быстрый анализ"
                print_info "Режим: Быстрый анализ (локальный)"
            fi
            ;;
        3)
            if [ ! -z "$VT_API_KEY" ]; then
                CMD="$CMD --online --vt-api-key $VT_API_KEY --extract-attachments"
                print_info "Режим: Полный анализ + извлечение вложений"
            else
                print_warning "API ключ не найден, выполняется быстрый анализ без извлечения"
                CMD="$CMD --extract-attachments"
                print_info "Режим: Быстрый анализ + извлечение вложений"
            fi
            ;;
        *)
            print_info "Режим: Быстрый анализ (локальный)"
            ;;
    esac
    
    echo ""
    print_step "Запуск анализа..."
    echo -e "${CYAN}───────────────────────────────────────────────────────────────────────────────${NC}"
    
    # Запуск анализа
    eval $CMD
    
    if [ $? -eq 0 ]; then
        print_success "Анализ успешно завершен!"
        echo ""
        print_info "Результаты сохранены в: $RESULT_DIR"
        echo "  • База данных: $RESULT_DIR/email_analysis.db"
        echo "  • HTML отчет: $RESULT_DIR/report.html"
        echo "  • CSV файлы: $RESULT_DIR/*.csv"
        
        # Сохраняем путь к БД для следующего шага
        LAST_DB_PATH="$RESULT_DIR/email_analysis.db"
        echo "$LAST_DB_PATH" > "$SCRIPT_DIR/.last_db_path"
        
        echo ""
        read -p "Запустить просмотрщик базы данных? (y/n): " RUN_VIEWER
        if [[ $RUN_VIEWER =~ ^[Yy]$ ]]; then
            run_viewer "$LAST_DB_PATH"
        fi
    else
        print_error "Ошибка при выполнении анализа"
        read -p "Нажмите Enter для продолжения..."
    fi
}

# Функция для просмотра базы данных
run_viewer() {
    local db_path="$1"
    
    print_header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                         👁️ ПРОСМОТР БАЗЫ ДАННЫХ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Если путь не передан, запрашиваем
    if [ -z "$db_path" ]; then
        # Проверяем последний использованный путь
        if [ -f "$SCRIPT_DIR/.last_db_path" ]; then
            LAST_DB=$(cat "$SCRIPT_DIR/.last_db_path")
            if [ -f "$LAST_DB" ]; then
                print_info "Последняя использованная база данных: $LAST_DB"
                read -p "Использовать этот путь? (y/n): " USE_LAST
                if [[ $USE_LAST =~ ^[Yy]$ ]]; then
                    db_path="$LAST_DB"
                fi
            fi
        fi
        
        if [ -z "$db_path" ]; then
            print_info "Укажите путь к файлу базы данных (.db)"
            echo ""
            print_info "Примеры:"
            echo "  • ./results/analysis_20241215_143022/email_analysis.db"
            echo "  • /home/kali/email_analysis/email_analysis.db"
            echo ""
            read -p "📁 Путь к базе данных: " db_path
        fi
    fi
    
    # Проверка существования файла
    if [ ! -f "$db_path" ]; then
        print_error "Файл базы данных не найден: $db_path"
        read -p "Нажмите Enter для продолжения..."
        return 1
    fi
    
    # Проверка наличия просмотрщика
    if [ ! -f "$SCRIPT_DIR/email_viewer.py" ]; then
        print_error "Файл email_viewer.py не найден!"
        read -p "Нажмите Enter для продолжения..."
        return 1
    fi
    
    print_success "База данных найдена: $db_path"
    
    # Получение информации о базе данных
    DB_SIZE=$(du -h "$db_path" | cut -f1)
    print_info "Размер базы данных: $DB_SIZE"
    
    echo ""
    print_step "Запуск просмотрщика..."
    echo -e "${CYAN}───────────────────────────────────────────────────────────────────────────────${NC}"
    
    # Запуск просмотрщика
    "$SCRIPT_DIR/run_viewer.sh" "$db_path"
    
    print_success "Просмотрщик завершил работу"
    read -p "Нажмите Enter для продолжения..."
}

# Функция для просмотра списка результатов
list_results() {
    print_header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                         📁 СПИСОК РЕЗУЛЬТАТОВ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ ! -d "$RESULTS_BASE_DIR" ]; then
        print_warning "Директория с результатами не найдена"
        mkdir -p "$RESULTS_BASE_DIR"
        print_success "Создана директория: $RESULTS_BASE_DIR"
        read -p "Нажмите Enter для продолжения..."
        return
    fi
    
    # Поиск всех директорий с анализом
    mapfile -t RESULTS_DIRS < <(find "$RESULTS_BASE_DIR" -maxdepth 1 -type d -name "analysis_*" | sort -r)
    
    if [ ${#RESULTS_DIRS[@]} -eq 0 ]; then
        print_warning "Результаты анализов не найдены"
        read -p "Нажмите Enter для продолжения..."
        return
    fi
    
    echo -e "${YELLOW}Найденные результаты анализов:${NC}"
    echo ""
    
    local i=1
    declare -A DB_MAP
    
    for dir in "${RESULTS_DIRS[@]}"; do
        local db_file="$dir/email_analysis.db"
        local dir_name=$(basename "$dir")
        local dir_date=${dir_name#analysis_}
        local dir_date_formatted=$(echo "$dir_date" | sed 's/\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)_\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)/\1-\2-\3 \4:\5:\6/')
        
        if [ -f "$db_file" ]; then
            local db_size=$(du -h "$db_file" | cut -f1)
            echo -e "  ${GREEN}[$i]${NC} $dir_date_formatted - ${CYAN}$db_size${NC}"
            DB_MAP[$i]="$db_file"
            ((i++))
        fi
    done
    
    echo ""
    echo "  [0] Назад"
    echo ""
    read -p "Выберите результат для просмотра (0-${#DB_MAP[@]}): " choice
    
    if [ "$choice" != "0" ] && [ -n "${DB_MAP[$choice]}" ]; then
        run_viewer "${DB_MAP[$choice]}"
    fi
}

# Функция для вывода информации о программе
show_about() {
    print_header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                         ℹ️ О ПРОГРАММЕ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${MAGENTA}📧 Email Parser (Empaser) - Комплексный анализ email сообщений${NC}"
    echo ""
    echo "Версия: 1.0"
    echo ""
    echo "Возможности:"
    echo "  • Извлечение писем из EML файлов (до 10000)"
    echo "  • Анализ отправителей (IP, домен, SPF/DKIM/DMARC)"
    echo "  • Извлечение вложений и вычисление хешей"
    echo "  • Проверка репутации через VirusTotal"
    echo "  • Обнаружение ссылок на облачные хранилища"
    echo "  • Создание HTML и CSV отчетов"
    echo "  • Интерактивный просмотр базы данных"
    echo ""
    echo "Системные требования:"
    echo "  • ОС: Linux (Kali, Ubuntu, Debian)"
    echo "  • Python 3.8+"
    echo "  • SQLite3"
    echo "  • Интернет (для онлайн-проверок)"
    echo ""
    echo "Автор: Email Analysis Suite"
    echo "Лицензия: MIT"
    echo ""
    read -p "Нажмите Enter для продолжения..."
}

# Главное меню
main_menu() {
    while true; do
        print_header
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}                         📋 ГЛАВНОЕ МЕНЮ${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        
        # Проверка статуса установки
        if check_installation >/dev/null 2>&1; then
            echo -e "  ${GREEN}✅ Статус: Установлено${NC}"
        else
            echo -e "  ${RED}❌ Статус: Не установлено${NC}"
        fi
        
        echo ""
        echo -e "${YELLOW}Выберите действие:${NC}"
        echo "  [1] 🔧 Установка зависимостей"
        echo "  [2] 🔑 Настройка API ключа VirusTotal"
        echo "  [3] 📧 Анализ писем (парсинг EML)"
        echo "  [4] 👁️ Просмотр базы данных"
        echo "  [5] 📁 Список результатов"
        echo "  [6] ℹ️ О программе"
        echo "  [0] 🚪 Выход"
        echo ""
        read -p "Ваш выбор: " choice
        
        case $choice in
            1) install_dependencies ;;
            2) setup_api_key ;;
            3) run_analysis ;;
            4) run_viewer ;;
            5) list_results ;;
            6) show_about ;;
            0) 
                print_success "До свидания!"
                exit 0
                ;;
            *)
                print_error "Неверный выбор"
                sleep 1
                ;;
        esac
    done
}

# Проверка наличия необходимых файлов при запуске
check_required_files() {
    local missing=()
    
    if [ ! -f "$SCRIPT_DIR/email_analyzer_advanced.py" ]; then
        missing+=("email_analyzer_advanced.py")
    fi
    
    if [ ! -f "$SCRIPT_DIR/email_viewer.py" ]; then
        missing+=("email_viewer.py")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_header
        print_error "Отсутствуют необходимые файлы:"
        for file in "${missing[@]}"; do
            echo "  • $file"
        done
        echo ""
        print_info "Пожалуйста, поместите все файлы в одну директорию:"
        echo "  • empaser.sh"
        echo "  • email_analyzer_advanced.py"
        echo "  • email_viewer.py"
        echo ""
        exit 1
    fi
}

# Запуск
check_required_files
main_menu
