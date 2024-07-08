INSTVIZ_HEADER = """
<style>
    .instviz {
        font-family: 'Courier New', monospace;
        text-align: center;
        border-collapse: collapse;
        border: 1px solid black;
        table-layout: fixed;
    }

    .instviz td {
        border: 1px solid black;
        padding: 1px;
    }

    .instviz .smoll {
        background: rgba(200, 200, 200);
        font-size: 11px;
    }

</style>

"""


class TableBuilder:
    # This is horrible, but it works well, I don't care.
    def __init__(self, classes="instviz", header=""):
        self.result = header
        self.result += f'<table class="{classes}">'

    def tr_start(self, classes=""):
        self.result += f'<tr class="{classes}">'

    def tr_end(self):
        self.result += "</tr>"

    def tbody_start(self):
        self.result += "<tbody>"

    def tbody_end(self):
        self.result += "</tbody>"

    def push(self, text, length=None, classes="", vertical=False, bg=None):
        self.result += f'<td class="{classes}"'
        style = ""
        if length:
            self.result += f' colspan="{length}"'
        if bg:
            style += f"background: {bg};"
        if vertical:
            style += "writing-mode: vertical-lr;width: 15px;"

        self.result += f' style="{style}">'

        self.result += text
        self.result += "</td>"

    def end(self):
        self.result += "</table>"

    def save(self, filename):
        file = open(filename, "w")
        file.write(self.result)
        file.close()
