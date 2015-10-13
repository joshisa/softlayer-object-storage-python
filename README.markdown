SoftLayer Object Storage Python Client
======================================
Python bindings for SoftLayer Object Storage

Installation
------------
Install via [pip](http://www.pip-installer.org):
```
pip install softlayer-object-storage
```

Or install from source:

```
git clone git://github.com/softlayer/softlayer-object-storage-python.git
cd softlayer-object-storage-python
python setup.py install
```

To build the documentation (requires sphinx):

```
python setup.py build_sphinx
```

Basic Usage
-----------

```python
import object_storage

sl_storage = object_storage.get_client('YOUR_USERNAME', 'YOUR_API_KEY', 'YOUR_BLUEMIX_AUTH_URL', datacenter='dal05')

sl_storage.containers()
# []

sl_storage['foo'].create()
# Container(foo)

sl_storage.containers()
# [Container(foo)]

sl_storage['foo'].properties
# {'count': 0, 'object_count': 0, 'name': 'foo', 'size': 0.0}

sl_storage['foo']['bar.txt'].create()
# StorageObject(foo, sample_object.txt)

sl_storage['foo']['bar.txt'].send('Plain-Text Content')
# True

sl_storage['foo']['bar.txt'].read()
# 'Plain-Text Content'

sl_storage['foo'].objects()
# [StorageObject(foo, bar.txt)]

sl_storage['foo']['bar.txt'].delete()
# True

sl_storage['foo'].delete()
# True
```

Search Usage
------------
```python
sl_storage.search('foo')
# {'count': 2, 'total': 2, 'results': [Container(foo), StorageObject(bar, foo)]}

sl_storage['foo'].search('bar.txt')
# {'count': 1, 'total': 1, 'results': [StorageObject(foo, bar.txt)]}

sl_storage.search('foo', type='container')
# {'count': 1, 'total': 1, 'results': [Container(foo)]}

sl_storage.search('foo*baz')
# {'count': 1, 'total': 1, 'results': [Container(foobarbaz)]}
```

Development
------------
Here's how to get started:

* Fork repo on github
* Clone your new repo to your local machine:

* ``` 
git clone git@github.com:username/softlayer-object-storage-python.git 
```

* Configure remote for upstream:

* ```
cd softlayer-object-storage-python
git remote add upstream git://github.com/softlayer/softlayer-object-storage-python.git
```
