__author__ = 'Administrator'
import unittest
import json
from base64 import b64encode
import re

from app import create_app, db
from app.models import User, Role, Post, Comment


class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def get_api_headers(self, username, password):
        return {'Authorization': 'Basic ' + b64encode((username + ":" + password).encode('utf-8')).decode('utf-8'),
                'Accept': 'application/json', 'Content-Type': 'application/json'}

    def test_404(self):
        response = self.client.get('/wrong/url', headers=self.get_api_headers('email', 'password'))
        self.assertEqual(response.status_code, 404)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['error'], 'not found')

    def test_no_auth(self):
        response = self.client.get('/api/v1/posts/', content_type='application/json')
        self.assertEqual(response.status_code, 401)

    def test_bad_auth(self):
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u = User(email='john@example.com', password='123456', confirmed=True, role=r)
        db.session.add(u)
        db.session.commit()
        response = self.client.get('/api/v1/posts/', headers=self.get_api_headers('john@example.com', '12345'))
        self.assertEqual(response.status_code, 401)

    def test_token_auth(self):
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u = User(email='john@example.com', password='123456', confirmed=True, role=r)
        db.session.add(u)
        db.session.commit()
        response = self.client.get('/api/v1/posts/', headers=self.get_api_headers('bad-token', ''))
        self.assertEqual(response.status_code, 401)

        response = self.client.post('/api/v1/tokens/', headers=self.get_api_headers('john@example.com', '123456'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        print(json_response)
        self.assertIsNotNone(json_response.get('token'))
        token = json_response['token']

        response = self.client.get('/api/v1/posts/', headers=self.get_api_headers(token, ''))
        self.assertEqual(response.status_code, 200)

    def test_anonymous(self):
        response = self.client.get('/api/v1/posts/', headers=self.get_api_headers('', ''))
        self.assertEqual(response.status_code, 401)

    def test_unconfirmed_user(self):
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u = User(email='john@example.com', password='123456', confirmed=False, role=r)
        db.session.add(u)
        db.session.commit()
        response = self.client.get('/api/v1/posts/', headers=self.get_api_headers('john@example.com', '123456'))
        self.assertEqual(response.status_code, 403)

    def test_posts(self):
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u = User(email='john@example.com', password='123456', confirmed=True, role=r)
        db.session.add(u)
        db.session.commit()
        response = self.client.post('/api/v1/posts/', headers=self.get_api_headers('john@example.com', '123456'),
                                    data=json.dumps({'body': ''}))
        self.assertEqual(response.status_code, 400)

        response = self.client.post('/api/v1/posts/', headers=self.get_api_headers('john@example.com', '123456'),
                                    data=json.dumps({'body': 'body of the *blog* post'}))
        self.assertEqual(response.status_code, 201)
        url = response.headers.get('Location')
        print(url)
        self.assertIsNotNone(url)

        response = self.client.get(url, headers=self.get_api_headers('john@example.com', '123456'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual('http://localhost' + json_response['url'], url)
        self.assertEqual(json_response['body'], 'body of the *blog* post')
        self.assertEqual(json_response['body_html'], '<p>body of the <em>blog</em> post</p>')
        json_post = json_response

        response = self.client.get('/api/v1/users/{}/posts/'.format(u.id),
                                   headers=self.get_api_headers('john@example.com', '123456'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertIsNotNone(json_response.get('posts'))
        self.assertEqual(json_response.get('count', 0), 1)
        self.assertEqual(json_response['posts'][0], json_post)

        response = self.client.put(url, headers=self.get_api_headers('john@example.com', '123456'),
                                   data=json.dumps({'body': 'updated body'}))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual('http://localhost' + json_response['url'], url)
        self.assertEqual(json_response['body'], 'updated body')
        self.assertEqual(json_response['body_html'], '<p>updated body</p>')

    def test_user(self):
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u1 = User(email='john@example.com', username='john', password='123456', confirmed=True, role=r)
        u2 = User(email='susan@example.org', username='susan', password='12345', confirmed=True, role=r)
        db.session.add_all([u1, u2])
        db.session.commit()

        response = self.client.get('/api/v1/users/{}'.format(u1.id),
                                   headers=self.get_api_headers('susan@example.org', '12345'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['username'], 'john')

        response = self.client.get('/api/v1/users/{}'.format(u2.id),
                                   headers=self.get_api_headers('susan@example.org', '12345'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['username'], 'susan')

    def test_comments(self):
        r = Role.query.filter_by(name='User').first()
        self.assertIsNotNone(r)
        u1 = User(email='john@example.com', username='john', password='123456', confirmed=True, role=r)
        u2 = User(email='susan@example.org', username='susan', password='12345', confirmed=True, role=r)
        db.session.add_all([u1, u2])
        db.session.commit()

        post = Post(body='body of the post', author=u1)
        db.session.add(post)
        db.session.commit()

        response = self.client.post('/api/v1/posts/{}/comments/'.format(post.id),
                                    headers=self.get_api_headers('susan@example.org', '12345'),
                                    data=json.dumps({'body': 'Good [post](http://example.com)!'}))
        self.assertEqual(response.status_code, 201)
        json_response = json.loads(response.get_data(as_text=True))
        url = response.headers.get('Location')
        print(url)
        print(json_response)
        self.assertIsNotNone(url)
        self.assertEqual(json_response['body'], 'Good [post](http://example.com)!')
        self.assertEqual(re.sub('<.*?>', '', json_response['body_html']), 'Good post!')

        response = self.client.get(url, headers=self.get_api_headers('john@example.com', '123456'))
        self.assertEqual(response.status_code,200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual('http://localhost'+json_response['url'],url)
        self.assertEqual(json_response['body'],'Good [post](http://example.com)!')

        comment = Comment(body='Thank you!',author=u1,post=post)
        db.session.add(comment)
        db.session.commit()

        response = self.client.get('/api/v1/posts/{}/comments/'.format(post.id), headers=self.get_api_headers('susan@example.org', '12345'))
        self.assertEqual(response.status_code,200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertIsNotNone(json_response.get('comments'))
        self.assertEqual(json_response.get('count',0),2)