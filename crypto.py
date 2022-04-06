import sys
import os
import ctypes
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QInputDialog, QLineEdit, QMessageBox
from PyQt5 import uic, QtWidgets
from PyQt5.QtGui import QIcon
import main


class Cryptor(QMainWindow):
    def __init__(self):
        super(Cryptor, self).__init__()
        uic.loadUi('UI_Design.ui', self)
        self.setWindowTitle('E-Kraal')
        self.Encrypt.clicked.connect(self.encrypty)
        self.Decrypt.clicked.connect(self.decrypty)
        self.FileUpload.clicked.connect(self.attach_file)
        self.Clear.clicked.connect(self.clear_text)
    # Encryption method
    def encrypty(self):
        self.plain = self.Text.toPlainText()
        if self.plain!='':
            self.setPasswd()
            print(self.spanner)
            ct=main.Ekraal.encrypt(self, pt=self.plain,encpasswd=self.spanner)
            self.Text.clear()
            self.Text.appendPlainText(ct)
        else:
            # change: Removed about
            QMessageBox.about(self,"Encryption status", "Nothing to encrypt")
    
  #Decryption method
    def decrypty(self):
        ctext=self.Text.toPlainText()
        if ctext !='':
            self.setPasswd()
            print(self.spanner)
            pt=main.Ekraal.decrypt(self, ct=ctext,passwd=self.spanner)
            print("pt123", pt)
            self.Text.clear()
            self.Text.appendPlainText(pt)
        else:
            # change: Removed about
            QMessageBox.about(self,"Decryption status", "Nothing to decrypt")
  
       
    def attach_file(self):
        options=QFileDialog.Options()
        options |=QFileDialog.DontUseNativeDialog
        fileName,_=QFileDialog.getOpenFileName(self, 'Select File',os.path.expanduser('~/Documentts'))
        if fileName:
            try:
                self.filename=fileName
                self.path.setText(fileName)
            except:
                return None
    
    
    def clear_text(self):
        beta=self.Text.toPlainText()
        alpha=self.path.Text()
        if beta !='':
            self.Text.clear()
        elif alpha!='':
            self.path.clear()
        else:
            QMessageBox.about(self,"Empty", "No Text to clear")
        if ctypes.windll.user32.OpenClipboard(None):
           ctypes.windll.user32.EmptyClipboard()
           ctypes.windll.user32.CloseClipboard()

    
    def setPasswd(self):
        text,ok=QInputDialog.getText(self,"Password","Kindly input password:",QLineEdit.Password,"")
        if text!='':
            if ok:
                self.spanner=text
                self.confirmPassword()
            else:
                if ok:
                    self.setEncryptPasswor()
                else:
                    pass
   

#define confirm password
    def confirmPassword(self):
        text,ok=QInputDialog.getText(self,"confirmation","Kindly re-enter the encryption password:")
        if text!='':
            if ok:
                nut=text
                if nut==self.spanner:
                    self.spanner=nut
                else:
                    QMessageBox.about(self,"Miss-Match","Password do not match\n please re-enter")
                    self.setpassword()
            else:
                pass
        else:
            if ok:
                QMessageBox.about(self, "Error","password not confirmed")
                self.EncryptPassword()
            else:
                pass
        

if __name__=="__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setWindowIcon(QIcon("icon.jpg"))
    window = Cryptor()
    window.setWindowTitle('E-kraal')
    window.show()
    sys.exit(app.exec_())