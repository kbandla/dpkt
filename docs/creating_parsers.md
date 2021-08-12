# Key concepts of creating protocol parsers in dpkt

by Oscar Ibatullin \[<https://github.com/obormot>\] a
contributor/maintainer of dpkt.

## Parser class definition

Let's look at the IPv4 parser, defined in `dpkt/ip.py`, as an example.

```python
class IP(dpkt.Packet):
    """Internet Protocol."""

    __hdr__ = (
        ('_v_hl', 'B', (4 << 4) | (20 >> 2)),
        ('tos', 'B', 0),
        ('len', 'H', 20),
        ('id', 'H', 0),
        ('_flags_offset', 'H', 0),
        ('ttl', 'B', 64),
        ('p', 'B', 0),
        ('sum', 'H', 0),
        ('src', '4s', b'\x00' * 4),
        ('dst', '4s', b'\x00' * 4)
    )
    __bit_fields__ = {
        '_v_hl': (
            ('v', 4),   # version, 4 bits
            ('hl', 4),  # header len, 4 bits
        ),
        '_flags_offset': (
            ('rf', 1),  # reserved bit
            ('df', 1),  # don't fragment
            ('mf', 1),  # more fragments
            ('offset', 13),  # fragment offset, 13 bits
        )
    }
    __pprint_funcs__ = {
        'dst': inet_to_str,
        'src': inet_to_str,
        'p': get_ip_proto_name
    }
```
A lot is going on in the header, before we even got to `__init__`\! Here
is the breakdown:

1.  Note the main `class IP` inherits from `dpkt.Packet`

2.  `__hdr__` defines a list of fields in the protocol header as 3-item
    tuples: *(field name, python struct format, default value)*. The
    fields are arranged in the order they appear on the wire.
    
    Field names generally follow the protocol definitions (e.g. RFC),
    but there are some rules to naming the fields that affect `dpkt`
    processing:
    
      * a name that doesn't start with an underscore represents a
        regular public protocol field. *Examples:* `tos`, `len`, `id`

      * a name that starts with an underscore and contains NO more
        underscores is considered private and gets hidden in `__repr__`
        and `pprint()` outputs; this is useful for hiding fields
        reserved for future use, or fields that should be decoded
        according to some custom rules. *Example:* `_reserved`
        
      * a name that starts with an underscore and DOES contain more
        underscores is similarly considered private and hidden, but gets
        processed as a collection of multiple protocol fields, separated
        by underscore. Each field name may contain up to 1 underscore as
        well. These fields are only created when the class definition
        contains matching property definitions, which could be defined
        explicitly or created automagically via `__bit_fields__` (more
        on this later). *Examples:*
        
        * `_foo_bar_m_flag` will map to fields named `foo`, `bar`,
          `m_flag`, when the class contains properties with these
          names (note `foo_bar_m` will be ignored since it
          contains two underscores).
        
        * in the IP class the `_v_hl` field itself is hidden in
          the output of `__repr__` and `pprint()`, and is decoded
          into `v` and `hl` fields that are displayed instead.
    
    The second component of the tuple specifies the format of the
    protocol field, as it corresponds to Python's native `struct`
    module. `'B'` means the field will decode to an unsigned byte, 
    `'H'` - to an unsigned word, etc. The default byte order is big 
    endian (network order). Endianness can be changed to little 
    endian by specifying `__byte_order__ = '<'` in the class 
    definition.

3.  Next, `__bit_fields__` is an optional dict that helps decode
    compound protocol fields, such as `_v_hl` or `_flags_offset` in the
    IP class. Each field name (as it appears in `__hdr__`) maps to a
    list (technically a tuple) of tuples, defining the bit fields in the
    network order (from high to low). Each tuple is *(bit field name,
    size in bits)*.
    
    The total sum of bit sizes must match the overall size of the
    placeholder field. For example, `_v_hl` is decoded to 1 byte
    (`'B'`), or 8 bits; `v` (the IP version) occupies the high 4 bits
    and `hl` (IP header length) occupies the lower 4 bits.
    
    `_flags_offset` that is 2 bytes long (`'H'`) is decoded into 3 1-bit
    flags followed by a 13-bit offset, total of 16 bytes.
    
    Similarly to the naming rules of `__hdr__`, a bit field name
    starting with an underscore is made invisible in the output.
    
    When dpkt processes `__bit_fields__` it auto-creates class
    properties that enable interfacing with the bit fields directly,
    specifically: get the value (`ip.v`), modify the value (`ip.v = 6`),
    and reset the value back to its default (`del ip.v`).
    
    In certain cases, auto-properties can't be applied; they still can
    be created explicitly. Look at `class SMB` inside `dpkt/smb.py` in
    how it decodes the `pid` protocol field.

4.  Next, `__pprint_funcs__` is an optional dict that does not control
    protocol decoding, but helps with pretty printing of the decoded
    packet using the `pprint()` method. Each key in this map is a name
    of the protocol field, and each value is a callable that will be run
    with a single argument of the protocol field value.
    
    For example, it's nice to see human readable IP addresses for `src`
    and `dst` fields by passing the raw bytes to `inet_to_str` function.

## Standard methods

Let's look at the standard methods of the `Packet` class and how they
contribute to parsing (aka unpacking or deserializing) and constructing
(aka packing or serializing) the packet.

```python
class IP(dpkt.Packet):
    ...
    def __init__(self, *args, **kwargs):
        super(IP, self).__init__(*args, **kwargs)
        ...

    def __len__(self):
        return self.__hdr_len__ + len(self.opts) + len(self.data)

    def __bytes__(self):
        # calculate IP checksum
        if self.sum == 0:
            self.sum = dpkt.in_cksum(self.pack_hdr() + bytes(self.opts))
        ...
        return self.pack_hdr() + bytes(self.opts) + bytes(self.data)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        ...
        self.opts = ...  # add IP options
        ...
        self.data = ...  # bytes that remain after unpacking

    def pack_hdr(self):
        buf = dpkt.Packet.pack_hdr(self)
        ...
        return buf
```
Instantiating the class with a bytes buffer (`ip = dpkt.ip.IP(buf)`)
will trigger the unpacking sequence as follows:

1.  `__init__(buf)` calls `self.unpack(buf)`
2.  `Packet.unpack()` creates protocol fields given in `__hdr__` as
    class attributes, and sets `self.data` to the remaining unparsed
    bytes in the buffer.

Child classes typically extend the `Packet.unpack()` method to create
additional custom attributes, that are not given in the `__hdr__` (such
as `opts` for IP options below).

Packing is the opposite of unpacking of course; given an instance of a
parsed packet, packing will return serialized packet as a `bytes` object
(`bytes(ip) => buf`). It goes as follows:

1.  Calling `bytes(obj)` invokes `self.__bytes__(obj)`

2.  `Packet.__bytes()__` calls `self.pack_hdr()` and returns its result
    with appended `bytes(self.data)`. The latter recursively triggers
    serialization of `self.data`, which could be another packet class,
    e.g. `Ethernet(.., data=IP(.., data=TCP(...)))`, so everything
    gets serialized.

3.  `Packet.pack_hdr()` iterates over the protocol fields given in
    `__hdr__`, calls `struct.pack()` on them and returns the resulting
    bytes.

Child classes typically extend the `Packet.__bytes__()` method to
process custom attributes, that are not given in the `__hdr__`, or to
override some values before `pack_hdr()` turns them into bytes. See how
the IP parser overrides `__bytes__` to calculate the IP checksum prior
to packing, and insert `bytes(self.opts)` between the packed header and
data.

### \_\_len\_\_

`__len__()` returns the size of the serialized packet and is typically
invoked when calling `len(obj)`. Note how in the IP class, this method
calls other functions to calculate size, then sums the lengths together,
and it **does not** perform serialization. It may be tempting to
implement `__len__` by serializing the packet into bytes and returning
the size of the resulting buffer (`return len(bytes(self))`). While this
works and is acceptable in some cases, dpkt views this as an
anti-pattern that should be avoided.

### \_\_repr\_\_ and pprint()

These methods are provided by `dpkt.Packet` and are typically not
overridden in the child class. However they are important to understand
when developing protocol parsers. Both `repr()` and `pprint()` are
responsible for the output, and both produce valid interpretable Python,
but there are some differences:

1.  `__repr__` returns a short one-liner printable string, while
    `pprint()` actually prints and returns nothing
2.  `__repr__` does not include protocol fields if their value is
    default, i.e. it will only display a field when it differs from the
    default. *Example:* in IPv4 the version always equals 4 so normally
    field `v` is not included.
3.  `pprint()` is verbose; its output is one field per line, indented,
    outdented and commented, and contrary to `__repr__` it includes all
    protocol fields, even when their value IS default.
4.  `__repr__` does not use the `__pprint_funcs__` and returns raw
    values. See below how `src` and `dst` IP addresses get human
    readable interpretation with `pprint()`, but not with `__repr__`.

```python
# repr()
>>> ip
IP(len=34, p=17, sum=29376, src=b'\x01\x02\x03\x04', dst=b'\x01\x02\x03\x04', opts=b'', data=UDP(sport=111, dport=222, ulen=14, sum=48949, data=b'foobar'))

# IP version field is default and is not returned by repr()
>>> ip.v
4

>>> ip.pprint()
IP(
  v=4,
  hl=5,
  tos=0,
  len=34,
  id=0,
  rf=0,
  df=0,
  mf=0,
  offset=0,
  ttl=64,
  p=17,  # UDP
  sum=29376,
  src=b'\x01\x02\x03\x04',  # 1.2.3.4
  dst=b'\x01\x02\x03\x04',  # 1.2.3.4
  opts=b'',
  data=UDP(
    sport=111,
    dport=222,
    ulen=14,
    sum=48949,
    data=b'foobar'
  )  # UDP
)  # IP
```
