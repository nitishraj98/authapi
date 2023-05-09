from django.core.mail import EmailMessage

class util:
    @staticmethod
    def send_email(data):
     email = EmailMessage(subject=data['subject'],body=data['body'],from_email='nitishtics@gmail.com',to=[data['to_email']])
     email.send() 