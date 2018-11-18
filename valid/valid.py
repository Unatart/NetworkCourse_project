import validate_email

MAX_LEN = 30
MIN_LEN = 1


class Validator():
    @staticmethod
    def validate_username(username):
        if username is None or len(username) < MIN_LEN or len(username) > MAX_LEN:
            return False
        for key in username:
            if not str(key).isalpha() and key not in "_." and not '0' <= key <= '9':
                return False
        return True

    @staticmethod
    def validate_password(password):
        return password is not None and MIN_LEN <= len(password) <= MAX_LEN

    @staticmethod
    def validate_email(email):
        return validate_email.validate_email(email)