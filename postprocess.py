import pandas as pd
import argparse
import sys

def postprocess(input_name, output_name):
    try:
        # Считываем CSV
        df = pd.read_csv(input_name)
    except FileNotFoundError:
        print(f"Ошибка: Файл '{input_name}' не найден.", file=sys.stderr)
        sys.exit(1)
    except pd.errors.EmptyDataError:
        print(f"Ошибка: Файл '{input_name}' пуст.", file=sys.stderr)
        sys.exit(1)
    except (pd.errors.ParserError, UnicodeDecodeError):
        print(f"Ошибка: Файл '{input_name}' повреждён или имеет неверный формат CSV.", file=sys.stderr)
        sys.exit(1)

    try:
        # Группируем по IP назначения (полученные пакеты)
        received_stats = (
            df.groupby("IP dest")
            .agg(
                received_packets=("Total packets", "sum"),
                received_bytes=("Total bytes", "sum"),
            )
            .reset_index()
        )

        # Группируем по IP источника (отправленные пакеты)
        sent_stats = (
            df.groupby("IP source")
            .agg(
                sent_packets=("Total packets", "sum"),
                sent_bytes=("Total bytes", "sum"),
            )
            .reset_index()
        )

        # Объединяем статистику по отправленным и полученным данным
        result = pd.merge(
            sent_stats,
            received_stats,
            left_on="IP source",
            right_on="IP dest",
            how="outer",
        )

        # Заполняем NaN среди числовых значений нулями
        for col in ["sent_packets", "sent_bytes", "received_packets", "received_bytes"]:
            result[col] = result[col].fillna(0)

        # Если какой-то IP адрес - NaN, значит он только отправлял либо только принимал
        result["IP source"] = result["IP source"].fillna(result["IP dest"])

        # Избавляемся от IP назначения
        result = result.drop(columns=["IP dest"])

        # Приводим к целочисленному типу
        for col in ["received_packets", "received_bytes", "sent_packets", "sent_bytes"]:
            result[col] = result[col].astype(int, errors="ignore")

        # Переименовываем столбцы
        result = result.rename(
            columns={
                "IP source": "IP address",
                "sent_packets": "Packets sent",
                "sent_bytes": "Bytes sent",
                "received_packets": "Packets received",
                "received_bytes": "Bytes received",
            }
        )

        # Сохраняем в CSV
        result.to_csv(output_name, index=False)
        print(f"Обработанные данные сохранены в '{output_name}'.")

    except KeyError as e:
        print(f"Ошибка: Отсутствует ожидаемый столбец во входном CSV: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Неожиданная ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Объект для считывания аргументов командной строки
    parser = argparse.ArgumentParser(
        description="Программа №2 из тестового задания для стажёра на позицию 'Разработчик C++/Python' (infotecs)"
    )

    # 2 аргумента - входной файл и выходной файл. Второй опционален - по умолчанию postprocess.csv
    parser.add_argument(
        "input_filename",
        help="Имя входного файла - результата работы программы №1.",
    )
    parser.add_argument(
        "output_filename",
        nargs="?",
        default="postprocess.csv",
        help="Имя выходного файла (по умолчанию: postprocess.csv)",
    )

    # Парсим аргументы
    args = parser.parse_args()

    # Вызываем postprocess() с переданными пользователем названиями файлов
    postprocess(args.input_filename, args.output_filename)
