import csv

def write_csv(path, table, header):
	"""
	Write table (list containing lists where each item is a row entry) to path with given header
	"""
	if path is None or header is None or table is None or len(table) == 0: return
	
	if not (type(table) == list and type(table[0] == list)): raise ValueError("Invalid type for table")

	with open(path, 'w', newline='') as file:
		writer = csv.writer(file, dialect='excel')
		writer.writerow(header)
		for entry in table: writer.writerow(entry)