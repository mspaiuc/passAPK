import json
import base64
import os
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.recycleview import RecycleView
from kivy.uix.recycleview.views import RecycleDataViewBehavior
from kivy.uix.recycleboxlayout import RecycleBoxLayout
from kivy.uix.behaviors import FocusBehavior
from kivy.uix.recycleview.layout import LayoutSelectionBehavior
from kivy.properties import BooleanProperty, StringProperty
from kivy.core.clipboard import Clipboard
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from kivy.utils import platform

# Constants
DATA_FILE = "passwords.enc"
FIXED_KEY = b"CHANGE_ME_IN_PROD_9876543210_CHANGE_ME"

def get_data_path():
    if platform == 'android':
        from android.storage import primary_external_storage_path
        dir_path = os.path.join(primary_external_storage_path(), 'PasswordManager')
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        return os.path.join(dir_path, DATA_FILE)
    return DATA_FILE

def get_key():
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"static_salt",
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(FIXED_KEY))

CIPHER_SUITE = Fernet(get_key())

class SelectableRecycleBoxLayout(FocusBehavior, LayoutSelectionBehavior,
                                 RecycleBoxLayout):
    ''' Adds selection and focus behaviour to the view. '''

class SelectableLabel(RecycleDataViewBehavior, BoxLayout):
    ''' Add selection support to the Label '''
    index = None
    selected = BooleanProperty(False)
    selectable = BooleanProperty(True)
    text = StringProperty("")

    def refresh_view_attrs(self, rv, index, data):
        ''' Catch and handle the view changes '''
        self.index = index
        self.text = f"{data['site']} - {data['username']}"
        return super(SelectableLabel, self).refresh_view_attrs(
            rv, index, data)

    def on_touch_down(self, touch):
        ''' Add selection on touch down '''
        if super(SelectableLabel, self).on_touch_down(touch):
            return True
        if self.collide_point(*touch.pos) and self.selectable:
            return self.parent.select_with_touch(self.index, touch)

    def apply_selection(self, rv, index, is_selected):
        ''' Respond to the selection of items in the view. '''
        self.selected = is_selected
        if is_selected:
            app = App.get_running_app()
            app.select_item(index)

class PasswordManagerKivyApp(App):
    def build(self):
        self.passwords = []
        self.current_selection = None
        self.load_passwords()

        root = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Form inputs
        self.site_input = TextInput(hint_text='Site / Aplicație', multiline=False, size_hint_y=None, height=40)
        self.user_input = TextInput(hint_text='Utilizator', multiline=False, size_hint_y=None, height=40)
        self.pass_input = TextInput(hint_text='Parolă', multiline=False, password=True, size_hint_y=None, height=40)
        self.details_input = TextInput(hint_text='Detalii', size_hint_y=None, height=60)

        root.add_widget(self.site_input)
        root.add_widget(self.user_input)
        root.add_widget(self.pass_input)
        root.add_widget(self.details_input)

        # Buttons
        btn_layout = BoxLayout(size_hint_y=None, height=50, spacing=10)
        save_btn = Button(text='Salvează', on_press=self.save_entry)
        clear_btn = Button(text='Curăță', on_press=self.clear_form)
        delete_btn = Button(text='Șterge', on_press=self.delete_entry)
        copy_btn = Button(text='Copiază Parola', on_press=self.copy_password)
        
        btn_layout.add_widget(save_btn)
        btn_layout.add_widget(clear_btn)
        btn_layout.add_widget(delete_btn)
        btn_layout.add_widget(copy_btn)
        root.add_widget(btn_layout)

        # List
        self.rv = RecycleView()
        self.rv.viewclass = 'SelectableLabel'
        self.rv.layout_manager = SelectableRecycleBoxLayout(default_size=(None, 56), default_size_hint=(1, None), size_hint_y=None, height=56, orientation='vertical')
        root.add_widget(self.rv)
        
        self.refresh_list()
        return root

    def load_passwords(self):
        file_path = get_data_path()
        if not os.path.exists(file_path):
            self.passwords = []
            return

        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
                if not encrypted_data:
                    self.passwords = []
                    return
                decrypted_data = CIPHER_SUITE.decrypt(encrypted_data)
                self.passwords = json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            self.show_popup("Eroare", f"Nu s-au putut încărca datele: {e}")
            self.passwords = []

    def save_passwords_to_disk(self):
        file_path = get_data_path()
        try:
            data_json = json.dumps(self.passwords)
            encrypted_data = CIPHER_SUITE.encrypt(data_json.encode("utf-8"))
            with open(file_path, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            self.show_popup("Eroare", f"Nu s-au putut salva datele: {e}")

    def save_entry(self, instance):
        site = self.site_input.text.strip()
        user = self.user_input.text.strip()
        password = self.pass_input.text.strip()
        details = self.details_input.text.strip()

        if not site or not user or not password:
            self.show_popup("Atenție", "Completează câmpurile obligatorii!")
            return

        entry = {
            "id": str(os.urandom(8).hex()) if not self.current_selection else self.current_selection['id'],
            "site": site,
            "username": user,
            "password": password,
            "details": details
        }

        if self.current_selection:
            for i, p in enumerate(self.passwords):
                if p["id"] == self.current_selection['id']:
                    self.passwords[i] = entry
                    break
            self.show_popup("Succes", "Parola actualizată!")
        else:
            self.passwords.append(entry)
            self.show_popup("Succes", "Parola salvată!")

        self.save_passwords_to_disk()
        self.clear_form(None)
        self.refresh_list()

    def clear_form(self, instance):
        self.site_input.text = ""
        self.user_input.text = ""
        self.pass_input.text = ""
        self.details_input.text = ""
        self.current_selection = None

    def refresh_list(self):
        self.rv.data = [{'site': p['site'], 'username': p['username']} for p in self.passwords]

    def select_item(self, index):
        if 0 <= index < len(self.passwords):
            entry = self.passwords[index]
            self.current_selection = entry
            self.site_input.text = entry['site']
            self.user_input.text = entry['username']
            self.pass_input.text = entry['password']
            self.details_input.text = entry['details']

    def delete_entry(self, instance):
        if self.current_selection:
            self.passwords = [p for p in self.passwords if p["id"] != self.current_selection['id']]
            self.save_passwords_to_disk()
            self.refresh_list()
            self.clear_form(None)
            self.show_popup("Info", "Intrare ștearsă!")

    def copy_password(self, instance):
        if self.current_selection:
            Clipboard.copy(self.current_selection['password'])
            self.show_popup("Info", "Parola copiată în clipboard!")

    def show_popup(self, title, content):
        popup = Popup(title=title, content=Label(text=content), size_hint=(None, None), size=(400, 200))
        popup.open()

if __name__ == '__main__':
    from kivy.lang import Builder
    Builder.load_string('''
<SelectableLabel>:
    # Draw a background to indicate selection
    canvas.before:
        Color:
            rgba: (.0, 0.9, .1, .3) if self.selected else (0, 0, 0, 1)
        Rectangle:
            pos: self.pos
            size: self.size
    Label:
        text: root.text
        pos: root.pos
        size: root.size
''')
    PasswordManagerKivyApp().run()
