from itertools import product
import curses

def run(callback, machine, rows, cols):
    def internal(stdscr, machine):
        console = ConsoleDisplay(stdscr, rows, cols)
        callback(console, machine)

    curses.wrapper(internal, machine)


class ConsoleDisplay():

    def __init__(self, win, rows, cols):
        def set_cursor_as_a_block():
            curses.curs_set(2)

        win.resize(rows, cols)
        win.keypad(1) # keys interpreted by curses
        win.nodelay(1) # getch is nonblocking
        set_cursor_as_a_block()
        self._win = win
        self.rows = rows
        self.cols = cols

    def set_char(self, x, y, ascii_value):
        if ascii_value == 0:
            ascii_value = 32
        self._win.insstr(y, x, str(chr(ascii_value)))


    def refresh(self, vram):
        for y, x in product(range(self.rows), range(self.cols)):
            self.set_char(x, y, vram[y * self.cols + x])
        self._win.refresh()
