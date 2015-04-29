#!/usr/bin/env python3

"""Semantic comparison of DOS MZ executables."""

from argparse import ArgumentParser
from collections import deque, namedtuple
from difflib import SequenceMatcher
import sys
from struct import unpack

parser = ArgumentParser(description=__doc__)
parser.add_argument('file1', help='Original file')
parser.add_argument('file2', help='Modified file')
parser.add_argument(
	'-c', '--color', action='store_true',
	help='Enable colored output',
)

MZHeader = namedtuple('MZHeader', [
	'magic',
	'bytes_on_last_page',
	'number_of_pages',
	'number_of_relocations',
	'header_paragraphs',
	'minimum_extra_allocation',
	'maximum_extra_allocation',
	'initial_relative_ss',
	'initial_sp',
	'checksum',
	'initial_ip',
	'initial_relative_cs',
	'relocation_table_offset',
	'overlay_number'
])
MZ_COL_LEN = max(len(i) for i in MZHeader._fields)

Reloc = namedtuple('Reloc', ['ofs', 'sgm'])

MZ = namedtuple('MZ', ['mz_header', 'mz_rest', 'relocs', 'rel_rest', 'prog'])


def read_to(file, pos):
	return file.read(pos - file.tell())


def hexdump(bytes, offset=0):
	BYTES_PER_LINE = 16

	def fmt_line(bytepos, line):
		return '%05X ' % (bytepos) + line

	if len(bytes) > BYTES_PER_LINE and bytes.count(0) == len(bytes):
		return [fmt_line(offset, ' (%Xh bytes of zero padding)' % len(bytes))]
	else:
		ret = []
		for i in range(0, len(bytes), BYTES_PER_LINE):
			line = ''.join(' %02X' % by for by in bytes[i:i + BYTES_PER_LINE])
			ret.append(fmt_line(i + offset, line))
	return ret


def mz_header_read(file):
	return MZHeader._make(unpack('<14H', file.read(14 * 2)))


def mz_header_fieldname_str(field):
	if field[-3] == '_':
		field = field[:-2] + field[-2:].upper()
	return field[0].upper() + field[1:].replace('_', ' ')


def mz_header_field_str(field, val):
	return '{:<{w}} {}'.format(
		mz_header_fieldname_str(field) + ':', '%4Xh' % val, w=MZ_COL_LEN + 1
	)


def mz_header_diff(mz_headers):
	ret = []
	for field in MZHeader._fields:
		vals = [getattr(i, field) for i in mz_headers]
		if vals[0] != vals[1]:
			ret.append('-' + mz_header_field_str(field, vals[0]))
			ret.append('+' + mz_header_field_str(field, vals[1]))
	return ret


def relocs_read(file, count):
	return frozenset({
		Reloc._make(unpack('<HH', file.read(4))) for i in range(count)
	})


def relocs_str(reloc):
	return "%04X:%04X" % (reloc.sgm, reloc.ofs)


def relocs_diff(relocs):
	return \
		['-' + relocs_str(i) for i in relocs[0] - relocs[1]] +\
		['+' + relocs_str(i) for i in relocs[1] - relocs[0]]


def binary_diff_str(bytes, op, offset=0):
	ret = []
	dump1 = hexdump(bytes[0][op[1]:op[2]], op[1] + offset)
	dump2 = hexdump(bytes[1][op[3]:op[4]], op[3] + offset)
	if op[0] == 'equal':
		ret += [' ' + i for i in dump1]
	if op[0] == 'replace' or op[0] == 'delete':
		ret += ['-' + i for i in dump1]
	if op[0] == 'replace' or op[0] == 'insert':
		ret += ['+' + i for i in dump2]
	return ret


def binary_diff(bytes):
	ret = []
	# Since SequenceMatcher is very, *very* slow, we first search for the
	# first byte that differs in both buffers in order to reduce the number of
	# bytes handed to that function.
	offset = 0
	for offset in range(min(len(bytes[0]), len(bytes[1]))):
		if bytes[0][offset] != bytes[1][offset]:
			break
	bytes = [i[offset:] for i in bytes]
	diff = SequenceMatcher(None, bytes[0], bytes[1])
	for i in diff.get_grouped_opcodes():
		for j in i:
			ret.extend(binary_diff_str(bytes, j, offset))
	return ret


def section_diff(diff_func, sct_val, sct_name, mzs):
	ret = deque(diff_func([getattr(i, sct_val) for i in mzs]))
	if len(ret):
		ret.appendleft(sct_name + ':')
		ret.append('')
	return list(ret)


def mz_read(fn):
	with open(fn, 'rb') as f:
		mz_header = mz_header_read(f)
		if mz_header.magic != 0x5A4D:
			sys.exit(
				"{}: '{}' is not a MZ executable.".format(sys.argv[0], fn)
			)
		return MZ(
			mz_header,
			read_to(f, mz_header.relocation_table_offset),
			relocs_read(f, mz_header.number_of_relocations),
			read_to(f, mz_header.header_paragraphs * 16),
			f.read()
		)


def mz_diff(files, color=True):
	mzs = [mz_read(fn) for fn in files]
	ret = deque(
		section_diff(mz_header_diff, 'mz_header', 'MZ header', mzs)
		+ section_diff(binary_diff, 'mz_rest', 'After MZ header', mzs)
		+ section_diff(relocs_diff, 'relocs', 'Relocations', mzs)
		+ section_diff(binary_diff, 'rel_rest', 'After relocations', mzs)
		+ section_diff(binary_diff, 'prog', 'Program image', mzs)
	)
	if len(ret):
		ret.appendleft('+++ ' + files[1] + '\n')
		ret.appendleft('--- ' + files[0])
		ret.pop() # remove final newline
	if color:
		from colorama import init, Fore, Style
		init()
		for i in ret:
			if len(i) and i[0] == '-':
				print(Fore.RED + Style.BRIGHT, end='')
			elif len(i) and i[0] == '+':
				print(Fore.GREEN + Style.BRIGHT, end='')
			print(i + Style.RESET_ALL)
	elif len(ret):
		print('\n'.join(ret))
	return len(ret) != 0


if __name__ == '__main__':
	arg = parser.parse_args()
	sys.exit(mz_diff((arg.file1, arg.file2), arg.color))
