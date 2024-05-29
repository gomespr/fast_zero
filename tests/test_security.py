from http import HTTPStatus

from jwt import decode

from fast_zero.security import create_access_token
from fast_zero.settings import Settings

settings = Settings()


def test_jwt():
    data = {'test': 'test'}
    token = create_access_token(data)

    decoded = decode(token, settings.SECRET_KEY, algorithms=['HS256'])

    assert decoded['test'] == data['test']
    assert decoded['exp']  # Testa se o valor de exp foi adicionado ao token


def test_get_current_user_credentials_exception_username(client, user, token):
    username_token = {'sub': ''}
    other_user_token = create_access_token(username_token)

    response = client.put(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {other_user_token}'},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json() == {'detail': 'Could not validate credentials'}


def test_get_current_user_credentials_exception_decoder(client, user, token):
    token_fake = 'test'

    response = client.put(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {token_fake}'},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json() == {'detail': 'Could not validate credentials'}


def test_get_current_user_credentials_exception_username_is_none(
    client, user, token
):
    username_token = {'sub': 'tob@example.com'}
    other_user_token = create_access_token(username_token)

    response = client.put(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {other_user_token}'},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json() == {'detail': 'Could not validate credentials'}
