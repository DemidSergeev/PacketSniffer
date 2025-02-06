import pandas as pd
import argparse

def postprocess(input_name, output_name):
	# Считываем CSV
	df = pd.read_csv(input_name)

	# Группируем по IP назначения (полученные пакеты)
	received_stats = df.groupby('IP dest').agg(
		received_packets = ('Total packets', 'sum'),
		received_bytes = ('Total bytes', 'sum')
	).reset_index()

	# Группируем по IP источника (отправленные пакеты)
	sent_stats = df.groupby('IP source').agg(
		sent_packets = ('Total packets', 'sum'),
		sent_bytes = ('Total bytes', 'sum')
	).reset_index()

	# Объединяем статистику по отправленным и полученным данным
	result = pd.merge(received_stats, sent_stats, left_on='IP source', right_on='IP dest', how='outer')

	# Заполняем NaN среди числовых значений нулями
	result[['sent_packets', 'sent_bytes', 'received_packets', 'received_bytes']] = result[['sent_packets', 'sent_bytes', 'received_packets', 'received_bytes']].fillna(0)

	# Если какой-то IP адрес - NaN, значит он только отправлял либо только принимал. Для IP source заменяем на соответствующий из IP dest
	result['IP source'] = result['IP source'].fillna(result['IP dest'])

	# Избавляемся от IP назначения
	result = result.drop(columns=['IP dest'])

	# Приводим к целочисленному типу
	result['received_packets'] = result['received_packets'].astype('int')
	result['received_bytes'] = result['received_bytes'].astype('int')
	result['sent_packets'] = result['sent_packets'].astype('int')
	result['sent_bytes'] = result['sent_bytes'].astype('int')

	# Переименовываем столбцы
	result = result.rename(columns={
	    'IP source': 'IP address',
	    'sent_packets':'Packets sent',
	    'sent_bytes':'Bytes sent',
	    'received_packets':'Packets received',
	    'received_bytes':'Bytes received'
	})

	# Сохраняем в CSV
	result.to_csv(output_name, index=False)

if __name__ == "__main__":
	# Объект для считывания аргументов командной строки
	parser = argparse.ArgumentParser(description="Программа №2 из тестового задания для стажёра на позицию 'Разработчик C++/Python' (infotecs)")

	# 2 аргумента - входной файл и выходной файл. Второй опционален - по умолчанию postprocess.csv
	parser.add_argument("input_filename", help="Имя входного файла - результата работы программы №1.")
	parser.add_argument("output_filename", nargs="?", default="postprocess.csv", help="Имя выходного файла (по умолчанию: postprocess.csv)")

	# Парсим аргументы
	args = parser.parse_args()

	# Вызываем postprocess() с переданными пользователем названиями файлов
	postprocess(args.input_filename, args.output_filename)
