from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication
from ui.main_window import Ui_MainWindow
from functools import partial
from PyPDF2 import PdfFileWriter, PdfFileReader, utils
from passwordgen import PasswordGenerator
import re
import sys


# Exception Decorator
def exception_handler(func):
    def wrap_function(self):
        try:
            func(self)
        except FileNotFoundError as e:
            pg = PyGUI()
            pg.info_messagebox(
                "The input file could not be loaded. Make sure it is still in the"
                " same location as when it was added",
                e.strerror,
            )
        except utils.PdfReadError:
            pg = PyGUI()
            pg.info_messagebox(
                "Cannot decrypt, password was incorrect or wrong/corrupted file",
            )

    return wrap_function


class PyGUI(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        self.watermark = ""
        super(PyGUI, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.app = None

        # Merge UI Interactions
        self.ui.mergeAdd.clicked.connect(
            partial(self.handle_add_files, self.ui.mergeList)
        )
        self.ui.mergeRemove.clicked.connect(
            partial(self.handle_remove_files, self.ui.mergeList)
        )
        self.ui.mergeClear.clicked.connect(
            partial(self.handle_clear_files, self.ui.mergeList)
        )
        self.ui.mergeRun.clicked.connect(self.handle_merge_files)

        # Split UI Interactions
        self.ui.splitAdd.clicked.connect(
            partial(self.handle_add_files, self.ui.splitList)
        )
        self.ui.splitRemove.clicked.connect(
            partial(self.handle_remove_files, self.ui.splitList)
        )
        self.ui.splitClear.clicked.connect(
            partial(self.handle_clear_files, self.ui.splitList)
        )
        self.ui.splitRun.clicked.connect(self.handle_split_files)

        # Watermark UI Interactions
        self.ui.watermarkAdd.clicked.connect(
            partial(self.handle_add_files, self.ui.watermarkList)
        )
        self.ui.watermarkRemove.clicked.connect(
            partial(self.handle_remove_files, self.ui.watermarkList)
        )
        self.ui.watermarkClear.clicked.connect(
            partial(self.handle_clear_files, self.ui.watermarkList)
        )
        self.ui.watermarkSelect.clicked.connect(self.handle_watermark_select)
        self.ui.watermarkRun.clicked.connect(self.handle_watermark_files)

        # Encryption UI Interactions
        self.ui.encryptionAdd.clicked.connect(
            partial(self.handle_add_files, self.ui.encryptionList)
        )
        self.ui.encryptionRemove.clicked.connect(
            partial(self.handle_remove_files, self.ui.encryptionList)
        )
        self.ui.encryptionClear.clicked.connect(
            partial(self.handle_clear_files, self.ui.encryptionList)
        )
        self.ui.encryptionEncrypt.clicked.connect(self.handle_encryption_files)
        self.ui.encryptionDecrypt.clicked.connect(self.handle_decryption_files)
        self.ui.encryptionRandom.clicked.connect(self.handle_random_password)
        self.ui.encryptionPassword.clicked.connect(self.handle_clipboard_password)

    # UI handling functions
    def handle_add_files(self, list):
        selected_files = self.add_files_dialog(True)
        if selected_files is not None:
            for file in selected_files:
                if not list.findItems(file, QtCore.Qt.MatchExactly):
                    list.addItem(file)

    def handle_remove_files(self, list):
        for index in list.selectionModel().selectedIndexes():
            list.takeItem(index.row())

    def handle_clear_files(self, list):
        list.clear()

    def handle_watermark_select(self):
        selected_files = self.add_files_dialog(False)
        if selected_files is not None:
            self.watermark = selected_files[0]
            self.ui.watermarkLabel.setText("Watermark file selected")
        else:
            self.watermark = ""
            self.ui.watermarkLabel.setText("No watermark selected...")

    # UI actions with exception handler decorator
    @exception_handler
    def handle_merge_files(self):
        files = []
        for index in range(self.ui.mergeList.count()):
            files.append(self.ui.mergeList.item(index).text())
        if not files == []:
            self.pdf_merge(files)
            self.info_messagebox("Files succesfully merged!", dicon=1)
        else:
            self.info_messagebox("Input files not selected!")

    @exception_handler
    def handle_split_files(self):
        files = []
        for index in range(self.ui.splitList.count()):
            files.append(self.ui.splitList.item(index).text())
        if not files == []:
            self.pdf_split(files)
            self.info_messagebox("File(s) succesfully split!", dicon=1)
        else:
            self.info_messagebox("Input files not selected!")

    @exception_handler
    def handle_watermark_files(self):
        files = []
        for index in range(self.ui.watermarkList.count()):
            files.append(self.ui.watermarkList.item(index).text())
        if not files == []:
            self.pdf_watermark(files)
            self.info_messagebox("File(s) succesfully watermarked!", dicon=1)
        else:
            self.info_messagebox("Input files not selected!")

    @exception_handler
    def handle_encryption_files(self):
        files = []
        for index in range(self.ui.encryptionList.count()):
            files.append(self.ui.encryptionList.item(index).text())
        if not files == []:
            self.pdf_encrypt(files)
            self.info_messagebox("File(s) succesfully encrypted!", dicon=1)
        else:
            self.info_messagebox("Input files not selected!")

    @exception_handler
    def handle_decryption_files(self):
        files = []
        for index in range(self.ui.encryptionList.count()):
            files.append(self.ui.encryptionList.item(index).text())
        if not files == []:
            self.pdf_decrypt(files)
            self.info_messagebox("File(s) succesfully decrypted!", dicon=1)
        else:
            self.info_messagebox("Input files not selected!")

    @exception_handler
    def handle_random_password(self):
        pwdgen = PasswordGenerator()
        self.ui.encryptionPassword.setText(pwdgen.generate_password())

    @exception_handler
    def handle_clipboard_password(self):
        if len(self.ui.encryptionPassword.text()) > 7:
            clipboard = self.app.clipboard()
            clipboard.clear(mode=clipboard.Clipboard)
            clipboard.setText(
                self.ui.encryptionPassword.text(), mode=clipboard.Clipboard
            )
            self.ui.encryptionPassword.selectAll()
            self.info_messagebox("Password copyied to clipboard!", dicon=1)

    # Other UI utils
    def info_messagebox(
        self, message, dicon=2, dtext="", dtitle="Missing or bad input"
    ):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(dicon)
        msg.setText(message)
        msg.setDetailedText(dtext)
        msg.setWindowTitle(dtitle)
        msg.exec_()

    def add_files_dialog(self, bool):
        dlg = QtWidgets.QFileDialog()
        if bool:
            dlg.setFileMode(QtWidgets.QFileDialog.ExistingFiles)
        else:
            dlg.setFileMode(QtWidgets.QFileDialog.ExistingFile)
        dlg.setNameFilters(["PDF Files (*.pdf)"])
        dlg.selectNameFilter("PDF Files (*.pdf)")
        if dlg.exec_():
            return dlg.selectedFiles()

    def save_files_dialog(self):
        dlg = QtWidgets.QFileDialog()
        dlg.setFileMode(QtWidgets.QFileDialog.DirectoryOnly)
        dlg.setAcceptMode(QtWidgets.QFileDialog.AcceptOpen)
        if dlg.exec_():
            return dlg.selectedFiles()

    # PDF Processing functions
    def pdf_merge(self, files):
        pdf_writer = PdfFileWriter()
        for file in files:
            pdf_reader = PdfFileReader(file)
            for page in range(pdf_reader.getNumPages()):
                pdf_writer.addPage(pdf_reader.getPage(page))
        name = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save merged PDF", "merged.pdf", "PDF Files (*.pdf)"
        )
        if len(name[0]) > 1:
            with open(name[0], "wb") as out:
                pdf_writer.write(out)

    def pdf_split(self, files):
        fname_pattern = r"[^\\|\/]([\\|\/][^\\\/]+)\.[^\\|\/]+"
        name = self.save_files_dialog()
        if str(self.ui.splitType.currentText()) == "Split all pages":
            for file in files:
                pdf_reader = PdfFileReader(file)
                for page in range(pdf_reader.getNumPages()):
                    pdf_writer = PdfFileWriter()
                    pdf_writer.addPage(pdf_reader.getPage(page))
                    path = (
                        name[0]
                        + re.search(fname_pattern, file).group(1)
                        + f"_page_{page}.pdf"
                    )
                    with open(path, "wb") as out:
                        pdf_writer.write(out)
        else:
            if len(files) < 2:
                pdf_reader = PdfFileReader(files[0])
                pdf_writer = PdfFileWriter()
                path = name[0] + re.search(fname_pattern, files[0]).group(1)
                splindex = 1
                for page in range(pdf_reader.getNumPages()):
                    if page + 1 < self.ui.splitPage.value():
                        pdf_writer.addPage(pdf_reader.getPage(page))
                    elif page + 1 == self.ui.splitPage.value():
                        pdf_writer.addPage(pdf_reader.getPage(page))
                        with open(path + f"_split_{splindex}.pdf", "wb") as out:
                            pdf_writer.write(out)
                        pdf_writer = PdfFileWriter()
                        splindex += 1
                    elif page + 1 == pdf_reader.getNumPages():
                        pdf_writer.addPage(pdf_reader.getPage(page))
                        with open(path + f"_split_{splindex}.pdf", "wb") as out:
                            pdf_writer.write(out)
                        pdf_writer = PdfFileWriter()
                    elif (
                        page + 1 > self.ui.splitPage.value()
                        and page < pdf_reader.getNumPages()
                    ):
                        pdf_writer.addPage(pdf_reader.getPage(page))
            else:
                self.info_messagebox("Page split only works with single file input!")

    def pdf_watermark(self, files):
        if not self.watermark == "":
            watermark_file = PdfFileReader(self.watermark)
            watermark_page = watermark_file.getPage(0)
            fname_pattern = r"[^\\|\/]([\\|\/][^\\\/]+)\.[^\\|\/]+"
            name = self.save_files_dialog()
            if len(name[0]) > 1:
                for file in files:
                    pdf_writer = PdfFileWriter()
                    pdf_reader = PdfFileReader(file)
                    for page in range(pdf_reader.getNumPages()):
                        page = pdf_reader.getPage(page)
                        page.mergePage(watermark_page)
                        pdf_writer.addPage(page)
                    path = (
                        name[0]
                        + re.search(fname_pattern, file).group(1)
                        + "_watermarked.pdf"
                    )
                    with open(path, "wb") as out:
                        pdf_writer.write(out)
        else:
            self.info_messagebox("Watermark file not selected!")

    def pdf_encrypt(self, files):
        if len(self.ui.encryptionPassword.text()) > 7:
            fname_pattern = r"[^\\|\/]([\\|\/][^\\\/]+)\.[^\\|\/]+"
            name = self.save_files_dialog()
            for file in files:
                pdf_writer = PdfFileWriter()
                pdf_reader = PdfFileReader(file)
                for page in range(pdf_reader.getNumPages()):
                    pdf_writer.addPage(pdf_reader.getPage(page))
                path = (
                    name[0]
                    + re.search(fname_pattern, file).group(1)
                    + f"_encrypted.pdf"
                )
                with open(path, "wb") as out:
                    pdf_writer.encrypt(self.ui.encryptionPassword.text())
                    pdf_writer.write(out)
        else:
            self.info_messagebox(
                "Password must be bigger than 8 characters!",
                dtitle="Password too short",
            )

    def pdf_decrypt(self, files):
        if len(self.ui.encryptionPassword.text()) > 7:
            fname_pattern = r"[^\\|\/]([\\|\/][^\\\/]+)\.[^\\|\/]+"
            name = self.save_files_dialog()
            for file in files:
                pdf_writer = PdfFileWriter()
                pdf_reader = PdfFileReader(file)
                pdf_reader.decrypt(self.ui.encryptionPassword.text())
                for page in range(pdf_reader.getNumPages()):
                    pdf_writer.addPage(pdf_reader.getPage(page))
                path = (
                    name[0]
                    + re.search(fname_pattern, file).group(1)
                    + f"_decrypted.pdf"
                )
                with open(path, "wb") as out:
                    pdf_writer.write(out)
        else:
            self.info_messagebox(
                "Password must be bigger than 8 characters!", "Password too short"
            )

    # Get QApplication for clipboard modification
    def get_qapp(self, qapp):
        self.app = qapp


def main():
    app = QApplication(sys.argv)
    form = PyGUI()
    form.show()
    form.get_qapp(app)
    app.exec_()


if __name__ == "__main__":
    main()
