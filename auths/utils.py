from rest_framework_simplejwt.tokens import AccessToken

def get_user_id_from_token(request):
    # Assuming the token is present in the Authorization header
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        try:
            # Extracting the token part from the header
            token = authorization_header.split(' ')[1] 
            # Decoding the token to retrieve the payload
            access_token = AccessToken(token)
            # Accessing the user ID from the decoded token payload
            user_id = access_token.payload.get('user_id')
            return user_id
        except IndexError:
            print("Authorization header is in an invalid format")
        except Exception as e:
            print(f"Error decoding token: {e}")
    return None 

def generate_random_string(length=15):
    import random, string
    # Define the characters you want to include in the random string
    characters = string.ascii_letters 

    # Generate a random string of the specified length
    random_string = ''.join(random.choice(characters) for _ in range(length))

    return random_string