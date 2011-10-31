#include <stdio.h>
#include "crypto/hash.h"
#include "util/ReadWriter.h"
#include "util/rw/MmapReader.h"
#include "util/rw/CompressedReader.h"
#include "compress/zlib.h"
#include <array>
#include <set>
#include <map>

std::map<std::string,std::string> keymap= {
    { "dn", "7F54B1D3-4653-4D59-B9E8-2AB8A405A5EB" },
    { "en", "6F6820A6-81A3-49A8-BAAA-10EFFC00E9BC" },
    { "fn", "97B57BD2-767B-41F1-ABAB-DD7C7B3F1F46" },
    { "nd", "8AF90274-27A3-49D2-84EC-8970FB500741" },
    { "ne", "99FC0E49-F040-4231-83F6-34FFCA99F517" },
    { "nf", "382CBAE0-3040-47CD-9306-B575955EDF58" },
    { "nn", "C50C00B1-EFE9-4718-8B87-7DD6E6C9FB5D" },
};
std::string getpath(const std::string& tag)
{
    return stringformat("/Volumes/SnowLeopard/Applications/Van Dale Woordenboeken/g%s3.vdw", tag.c_str());
}
void calcmd5key(const std::string&key, uint8_t*md5key)
{
    std::Wstring wkey= ToWString(key);

    Md5 m;
    m.add((const uint8_t*)&wkey[0], wkey.size()*2);
    m.final(md5key);

    for (int i=0 ; i<15 ; i++)
    {
        Md5 mi;
        mi.add(md5key+i*16, 16);
        mi.final(md5key+i*16+16);
    }
}
template<typename T>
struct circular_iterator {

    typedef typename T::value_type value_type;
    typedef value_type& reference;
    typedef value_type* pointer;
    typedef int difference_type;
    typedef std::random_access_iterator_tag iterator_category;

    typename T::const_iterator first;
    typename T::const_iterator last;
    typename T::const_iterator p;

    circular_iterator(const T& v)
        : first(v.begin()), last(v.end()), p(first)
    {
    }
    value_type operator*()
    {
        return *p;
    }
    // prefix inc
    circular_iterator& operator++()
    {
        ++p;
        if (p==last)
            p= first;
        return *this;
    }
    // postfix inc
    circular_iterator operator++(int)
    {
        circular_iterator  copy= *this;
        operator++();
        return copy;
    }
    void setpos(size_t n)
    {
        p= first + n%(last-first);
    }

//  circular_iterator& operator+=(int n) { p= first+(p-first+n)%(last-first); return *this; }
//  circular_iterator operator+(int n) { return circular_iterator(first, last, ); }
//  circular_iterator& operator-=(int n) { _blocknr-=n; return *this; }
//  circular_iterator operator-(int n) { return circular_iterator(_bi, _r, _blocknr-n); }
//  int operator-(const circular_iterator&rhs) const { return blocknr()-rhs.blocknr(); }

//  bool operator==(const circular_iterator&rhs) const { return blocknr()==rhs.blocknr(); }
//  bool operator!=(const circular_iterator&rhs) const { return blocknr()!=rhs.blocknr(); }
//  bool operator<=(const circular_iterator&rhs) const { return blocknr()<=rhs.blocknr(); }
//  bool operator< (const circular_iterator&rhs) const { return blocknr()< rhs.blocknr(); }
//  bool operator>=(const circular_iterator&rhs) const { return blocknr()>=rhs.blocknr(); }
//  bool operator> (const circular_iterator&rhs) const { return blocknr()> rhs.blocknr(); }

};
template<typename V>
circular_iterator<V> makecircular(const V&v)
{
    return circular_iterator<V>(v);
}

class xorreader : public ReadWriter {
    circular_iterator<std::vector<uint8_t> > _x;
    const uint8_t *_first;
    const uint8_t *_last;
    const uint8_t *_cur;
public:
    xorreader(const std::vector<uint8_t>& key, const uint8_t *first, const uint8_t*last)
        : _x(key), _first(first), _last(last), _cur(_first)
    {
    }
    virtual size_t read(uint8_t *p, size_t n)
    {
        size_t want= std::min(n, size_t(_last-_cur));
        for (size_t i= 0 ; i<want ; i++)
            *p++ = *_cur++ ^ *_x++;
        return want;
    }
    virtual void write(const uint8_t *p, size_t n)
    {
        throw "xorreader is readonly";
    }
    virtual void setpos(uint64_t off)
    {
        if (off > size())
            throw "xor.setpos: pos too large";
        _cur= _first+off;
        _x.setpos(off);
    }
    virtual void truncate(uint64_t off)
    {
        throw "xorreader is readonly";
    }
    virtual uint64_t size()
    {
        return _last-_first;
    }
    virtual uint64_t getpos() const
    {
        return _cur-_first;
    }
    virtual bool eof()
    {
        return _cur==_last;
    }
};

class Section {
    const std::vector<uint8_t>& M;
    uint32_t _type;
    const uint8_t* _first;
    const uint8_t* _last;
public:
    Section(const std::vector<uint8_t>& M, uint32_t type, const uint8_t* first, const uint8_t* last)
        : M(M), _type(type), _first(first), _last(last)
    {
    }

    ReadWriter_ptr makexorreader(uint32_t ofs, uint32_t len)
    {
        return ReadWriter_ptr(new xorreader(M, _first+ofs, _first+ofs+len));
    }
    ReadWriter_ptr makehdrreader()
    {
        return makexorreader(0x10, headersize());
    }

    const uint8_t* getptr(uint32_t ofs)
    {
        return _first+ofs;
    }
    uint32_t size()
    {
        return _last-_first;
    }

    std::string readstr(ReadWriter_ptr r)
    {
        uint32_t p= r->read32le();
        uint32_t l1= r->read32le();
        /*uint32_t l2=*/ r->read32le();

        return readstr(p, l1);
    }
    std::string readstr(uint32_t p, uint32_t l)
    {
        ReadWriter_ptr srd= makexorreader(p, l);

        return srd->readstr();
    }

    void verify()
    {
        Md5 hash;
        std::array<uint8_t,Md5::DigestSize> digest;
        hash.add(getptr(16), size()-16);
        hash.final(&digest.front());

        if (!std::equal(digest.begin(), digest.end(), getptr(0))) {
            printf("hash mismatch\n");
            throw "md5 error";
        }
        printf("section %08x ok\n", type());
        if (headersize()) {
            verifyheader();
        }

        verifysection();
    }
    void verifyheader()
    {
        ReadWriter_ptr hdr= makehdrreader();
        ByteVector hdrdata(headersize());
        hdr->read(&hdrdata[0], headersize());

        Md5 hash;
        std::array<uint8_t,Md5::DigestSize> digest;
        hash.add(&hdrdata[16], hdrdata.size()-16);
        hash.final(&digest.front());

        if (!std::equal(digest.begin(), digest.end(), &hdrdata[0])) {
            printf("hash mismatch\n");
            throw "md5 error";
        }
        printf("section header %08x ok\n", type());
    }
    virtual void verifysection() { }
    uint32_t type() const { return _type; }
    virtual uint32_t headersize() const { return 0; }

};

class RootSection : public Section {

    struct indexptr {
        uint32_t type;
        uint32_t ofs;
        uint32_t size;

        indexptr( uint32_t type, uint32_t ofs, uint32_t size)
            : type(type), ofs(ofs), size(size)
        {
        }
    };
    std::vector<indexptr> _ixlist;
    std::string _str1;
    std::string _str2;
    std::string _str3;

    void readindex(ReadWriter_ptr r)
    {
        uint32_t ofs= r->read32le();
        uint32_t len= r->read32le();

        printf("index[%08x %08x]\n", ofs, len);

        ReadWriter_ptr I= makexorreader(ofs, len);
        uint32_t count= I->read32le();
        for (unsigned i=0 ; i<count ; i++)
        {
            uint32_t type= I->read32le();
            if (type==0x10001 || (type>>16)==5) {
                uint32_t gofs= I->read32le();
                uint32_t glen= I->read32le();
                printf("%08x: %08x %08x\n", type, gofs, glen);
                _ixlist.push_back(indexptr(type, gofs, glen));
            }
            else if (type==0x20001) {
                uint32_t gofs= I->read32le();
                uint32_t glen= I->read32le();
                uint32_t unk= I->read32le();
                printf("%08x: %08x %08x [ %08x ]\n", type, gofs, glen, unk);
                //dumpblobsection(M, filebase,siz, ptr);
                _ixlist.push_back(indexptr(type, gofs, glen));
            }
            else if ((type>>16)==3) {
                uint32_t gofs= I->read32le();
                uint32_t glen= I->read32le();
                printf("%08x: %08x %08x [ %08x %08x ]\n", type, gofs, glen, I->read32le(), I->read32le());
                _ixlist.push_back(indexptr(type, gofs, glen));
            }
            else {
                printf("unknown [c=%x, t=%08x, i=%d]\n", count, type, i);
                break;
            }
        }
    }


public:
    virtual uint32_t headersize() const { return 0xc0; }

    RootSection(const std::vector<uint8_t>& M, uint32_t type, const uint8_t* first, const uint8_t* last)
        : Section(M, type, first, last)
    {
        ReadWriter_ptr hdr= makehdrreader();

        hdr->setpos(16);
        printf("%08x %08x %08x  section\n", hdr->read32le(), hdr->read32le(), hdr->read32le());

        _str1= readstr(hdr);  printf("str1: %s\n", _str1.c_str());
        _str2= readstr(hdr);  printf("str2: %s\n", _str2.c_str());
        _str3= readstr(hdr);  printf("str3: %s\n", _str3.c_str());
        printf("%08x %08x %08x  unk\n", hdr->read32le(), hdr->read32le(), hdr->read32le());

        readindex(hdr);
        readindex(hdr);
        printf("%08x %08x       dw+strings\n", hdr->read32le(), hdr->read32le());
        readindex(hdr);
        readindex(hdr);
        for (int i=5 ; i<12 ; i++)
            printf("%08x %08x       pix%d\n", hdr->read32le(), hdr->read32le(), i);
    }
    bool getsection(unsigned n, uint32_t *ofs, uint32_t *len, uint32_t *type)
    {
        if (n>=_ixlist.size())
            return false;

        auto i= _ixlist.begin()+n;
        *ofs= i->ofs;
        *len= i->size;
        *type= i->type;
        return true;
    }
};
typedef boost::shared_ptr<RootSection> RootSection_ptr;

class BlobSection : public Section {
    uint32_t _nitems;
    uint32_t _pblob;
    uint32_t _sblob;
           
    uint32_t _ptab;
    uint32_t _stab;
    std::string _shortname;
    std::string _longname;
#if 0
    void decompress(uint32_t blobofs)
    {
        auto uint8_t *p= getptr(_pblob)+blobofs;

        uint32_t size= get32le(p);

        ZlibDecompress z;
        z.add(p+4, size);

        ByteVector data;
        while (!z.eof())
        {
            data.resize(data.size()+0x10000);
            size_t n= z.get(&data[data.size()-0x10000], 0x10000);
            data.resize(data.size()-0x10000+n);
        }
        fwrite(&data[0], data.size(),1, stdout);
    }
    void dumpblobsection(uint32_t ofs, uint32_t len)
    {
        ReadWriter_ptr T= makexorreader(ofs, len);

        std::set<uint32_t> ptrs;
        while (!T->eof())
        {
            ptrs.insert(T->read32le());
            T->read32le();
            T->read32le();
            T->read16le();
        }
        for (auto i=ptrs.begin() ; i!=ptrs.end() ; ++i)
            decompress(*i);
    }
#endif
public:
    virtual uint32_t headersize() const { return 0xd0; }

    BlobSection(const std::vector<uint8_t>& M, uint32_t type, const uint8_t* first, const uint8_t* last)
        : Section(M, type, first, last)
    {
        ReadWriter_ptr hdr= makehdrreader();

        hdr->setpos(0x10);
        printf("%08x %08x %08x %08x  section\n", hdr->read32le(), hdr->read32le(), hdr->read32le(), hdr->read32le());

        _nitems= hdr->read32le();
        hdr->setpos(0x38);
        _pblob= hdr->read32le();
        _sblob= hdr->read32le();

        _ptab= hdr->read32le();
        _stab= hdr->read32le();

        //dumpblobsection(_ptab, _stab);

        _shortname= readstr(hdr);
        _longname= readstr(hdr);
    }
    std::string readitem(uint32_t ix)
    {
        if (ix>=_nitems)
            throw "item index too large";
        ReadWriter_ptr I= makexorreader(_ptab, _stab);
        I->setpos(14*ix);

        uint32_t blobofs= I->read32le();
        uint32_t streamofs= I->read32le();
        uint32_t itemsize= I->read32le();
        /*uint32_t unknul=*/ I->read16le();

        //printf("B+%08x, S+%08x/%08x\n", blobofs, streamofs, itemsize);

        uint32_t chunksize= get32le(getptr(_pblob)+blobofs);

        ReadWriter_ptr B= ReadWriter_ptr(new MemoryReader(getptr(_pblob)+blobofs+4, chunksize));
        ReadWriter_ptr Z= ReadWriter_ptr(new CompressedReader(B));

        return Z->readstr(streamofs, itemsize);
    }

    void dumpinfo()
    {
        printf("n=%d, blob:%x/%d, tab:%x/%d\n", _nitems, _pblob, _sblob, _ptab, _stab);
        for (unsigned i=0 ; i<_nitems ; i+=_nitems/16)
            printf("%8d : %s\n", i, readitem(i).c_str());
    }
};
typedef boost::shared_ptr<BlobSection> BlobSection_ptr;

class IndexSection : public Section {
    std::string _str1;
    std::string _str2;

    uint32_t _count1;
    uint32_t _count2;
    uint32_t _ptable1;
    uint32_t _ptable2;
    uint32_t _ptable3;
    uint32_t _pwords;
    uint32_t _ptable4;
    uint32_t _ptable5;
    uint32_t _lwords;

public:
    virtual uint32_t headersize() const { return (type()&0xfffffff0)==0x0030100 ? 0xb4 : 0xc0; }

    IndexSection(const std::vector<uint8_t>& M, uint32_t type, const uint8_t* first, const uint8_t* last)
        : Section(M, type, first, last),
            _count1(0), _count2(0), _ptable1(0), _ptable2(0), _ptable3(0),
            _pwords(0), _ptable4(0), _ptable5(0), _lwords(0)
    {
        ReadWriter_ptr hdr= makehdrreader();
        hdr->setpos(0x10);
        printf("idx: %08x %08x %08x %08x\n", hdr->read32le(), hdr->read32le(), hdr->read32le(), hdr->read32le());
        uint32_t pstr1= hdr->read32le();
        uint32_t pstr2= hdr->read32le();

        uint32_t lstr1= hdr->read32le();
        hdr->read32le();
        uint32_t lstr2= hdr->read32le();
        hdr->read32le();

        _str1= readstr(pstr1, lstr1);
        _str2= readstr(pstr2, lstr2);

        hdr->setpos(0x48);
        _count1= hdr->read32le();
        hdr->read32le();
        _count2= type==0x00030206 ? hdr->read32le() : 0;
        hdr->read32le();
        hdr->read32le();
        _ptable1= hdr->read32le();
        _ptable2= hdr->read32le();
        _ptable3= hdr->read32le();
        hdr->read32le();
        _pwords= hdr->read32le();
        _ptable4= type==0x00030206 ? hdr->read32le() : 0;
        _ptable5= type==0x00030206 ? hdr->read32le() : 0;
        hdr->read32le();
        _lwords= hdr->read32le();

        // todo: bitmap
        //
//      if (_ptable4)
//          dump45();
//      else
//          dump3();
    }
    std::string getword(uint32_t ix)
    {
        if (ix>=_count1)
            throw "index out of range";
        ReadWriter_ptr rt3= makexorreader(_ptable3, 4*_count1);
        rt3->setpos(4*ix);
        uint32_t wofs= rt3->read32le();
        uint32_t eofs= (ix==_count1-1) ? _lwords : rt3->read32le();

        ReadWriter_ptr wrd= makexorreader(_pwords, _lwords);

        return wrd->readstr(wofs+2, eofs-wofs);
    }
    void dump45()
    {
        printf("3:%08x/%d, 4:%08x/%d, 5:%08x/%d, w:%08x/%d\n",
                _ptable3, _count1,
                _ptable4, _count2,
                _ptable5, _count2,
                _pwords, _lwords);
        ReadWriter_ptr rt4= makexorreader(_ptable4, 6*_count2);
        ReadWriter_ptr rt5= makexorreader(_ptable5, 4*_count2);
        ReadWriter_ptr rtw= makexorreader(_pwords, _lwords);
        ReadWriter_ptr rt3= makexorreader(_ptable3, 4*_count1);

        std::vector<uint32_t> t4o;
        std::vector<uint16_t> t4l;
        std::vector<uint32_t> t5;
        std::vector<uint32_t> t3o;
        std::vector<std::string> tw;

        for (unsigned i=0 ; i<_count1 ; i++) {
            t3o.push_back(rt3->read32le());
        }
        while (!rtw->eof()) {
            uint16_t slen= rtw->read16le();
            std::string str; str.resize(slen);
            rtw->read((uint8_t*)&str[0], slen);
            tw.push_back(str);
        }
        for (unsigned i=0 ; i<_count2 ; i++) {
            t4o.push_back(rt4->read32le());
            t4l.push_back(rt4->read16le());
        }
        for (unsigned i=0 ; i<_count2 ; i++) {
            t5.push_back(rt5->read32le());
        }
        printf("3:%llx/%d 4:%llx/%d 5:%llx/%d w:%llx/%d\n",
                rt3->getpos(), rt3->eof(),
                rt4->getpos(), rt4->eof(),
                rt5->getpos(), rt5->eof(),
                rtw->getpos(), rtw->eof());

        for (unsigned i=0 ; i<_count2 ; i++)
        {
            std::string& s= tw[t5[i]];
            printf("%08x: 4[%08x/%04x]  5[%08x->%08x] %*s%s\n",
                    i, t4o[i], t4l[i], t5[i], t3o[t5[i]], 35-t4l[i], "", s.c_str());

        }
    }
    void dump3()
    {
        ReadWriter_ptr rtw= makexorreader(_pwords, _lwords);
        ReadWriter_ptr rt3= makexorreader(_ptable3, 4*_count1);

        std::vector<uint32_t> t3o;
        std::vector<std::string> tw;

        for (unsigned i=0 ; i<_count1 ; i++) {
            t3o.push_back(rt3->read32le());
        }
        while (!rtw->eof()) {
            uint16_t slen= rtw->read16le();
            std::string str; str.resize(slen);
            rtw->read((uint8_t*)&str[0], slen);
            tw.push_back(str);
        }
        printf("3:%llx/%d  w:%llx/%d\n",
                rt3->getpos(), rt3->eof(),
                rtw->getpos(), rtw->eof());

        for (unsigned i=0 ; i<_count1 ; i++)
        {
            printf("%08x: 3[%08x]'%s'\n",
                    i, t3o[i], tw[i].c_str());
        }
    }

    struct lessthen {
        bool operator()(const std::string &l, const std::string &r)
        {
            // todo: utf8 stringcompare ( which correctly handles multibyte characters
            return stringicompare(l,r)<0;
        }
    };
    // returns set of headword indexes matching str
    std::set<uint32_t> stringsearch(const std::string& str)
    {
        lessthen lt;
        ReadWriter_ptr rtw= makexorreader(_pwords, _lwords);
        ReadWriter_ptr rt3= makexorreader(_ptable3, 4*_count1);

        auto first= stringiterator(rt3, rtw, 0);
        auto last= stringiterator(rt3, rtw, _count1);
        auto i= std::lower_bound(first, last, str, lt);
        //  *i<str && str<=*(i+1)    .. str < *(i+n)
        if (i==last)
            return std::set<uint32_t>();

        ++i;

        ReadWriter_ptr rt1= makexorreader(_ptable1, 4*_count1);
        std::set<uint32_t> items;
        while (i!=last && !lt(str, *i)) {
            items.insert(rt1->read32le(4*i.index()));
            ++i;
        }
        return items;
    }

    // returns set of headword indexes matching str
    std::set<uint32_t> substrsearch(const std::string& str)
    {
        lessthen lt;
        ReadWriter_ptr rtw= makexorreader(_pwords, _lwords);
        ReadWriter_ptr rt4= makexorreader(_ptable4, 6*_count2);

        auto first= substriterator(rt4, rtw, 0);
        auto last= substriterator(rt4, rtw, _count2);
        auto i= std::lower_bound(first, last, str, lt);
        //  *i<str && str<=*(i+1)    .. str < *(i+n)
        if (i==last)
            return std::set<uint32_t>();

        ReadWriter_ptr rt5= makexorreader(_ptable5, 4*_count2);
        ReadWriter_ptr rt1= makexorreader(_ptable1, 4*_count1);
        std::set<uint32_t> items;
        while (i!=last && !lt(str, *i)) {
            uint32_t t5val= rt5->read32le(4*i.index());
            items.insert(rt1->read32le(4*t5val));
            ++i;
        }
        return items;
    }

    class iterator {
    protected:
        ReadWriter_ptr _tab;
        ReadWriter_ptr _words;
        uint32_t _ix;
    public:
        typedef std::string& reference;
        typedef std::string* pointer;
        typedef int difference_type;
        typedef std::string value_type;
        typedef std::random_access_iterator_tag iterator_category;

        iterator(ReadWriter_ptr tab, ReadWriter_ptr words, uint32_t ix)
            : _tab(tab), _words(words), _ix(ix)
        {
        }
        iterator()
            : _ix(0)
        {
        }
        iterator& operator++()
        {
            _ix++;
            return *this;
        }
        iterator operator++(int)
        {
            iterator copy= *this;
            operator++();
            return copy;
        }
        iterator& operator+=(int n) { _ix+=n; return *this; }
        iterator operator+(int n) { return iterator(_tab, _words, _ix+n); }
        iterator& operator-=(int n) { _ix-=n; return *this; }
        iterator operator-(int n) { return iterator(_tab, _words, _ix-n); }
        int operator-(const iterator&rhs) const { return _ix-rhs._ix; }

        bool operator==(const iterator&rhs) const { return _ix==rhs._ix; }
        bool operator!=(const iterator&rhs) const { return _ix!=rhs._ix; }
        bool operator<=(const iterator&rhs) const { return _ix<=rhs._ix; }
        bool operator< (const iterator&rhs) const { return _ix< rhs._ix; }
        bool operator>=(const iterator&rhs) const { return _ix>=rhs._ix; }
        bool operator> (const iterator&rhs) const { return _ix> rhs._ix; }

        uint32_t index() const { return _ix; }
    };


    class stringiterator : public iterator {
    public:
        stringiterator(ReadWriter_ptr tab, ReadWriter_ptr words, uint32_t ix)
            : iterator(tab, words, ix)
        {
        }
        stringiterator() { }
        std::string operator*()
        {
            _tab->setpos(4*_ix);
            uint32_t wofs= _tab->read32le();
            _words->setpos(wofs);
            uint16_t wlen= _words->read16le();

            return _words->readstr(wlen);
        }
    };

    class substriterator : public iterator {
    public:
        substriterator(ReadWriter_ptr tab, ReadWriter_ptr words, uint32_t ix)
            : iterator(tab, words, ix)
        {
        }
        substriterator() { }
        std::string operator*()
        {
            _tab->setpos(6*_ix);
            uint32_t wofs= _tab->read32le();
            uint16_t strofs= _tab->read16le();
            _words->setpos(wofs);
            uint16_t wlen= _words->read16le();

            return _words->readstr(wofs+2+strofs, wlen-strofs);
        }
    };
};
typedef boost::shared_ptr<IndexSection> IndexSection_ptr;

class VdwFile : public Section {

    RootSection_ptr _root;
    std::vector<BlobSection_ptr> _blobs;
    std::vector<IndexSection_ptr> _indices;
    uint32_t _cplen;

    ReadWriter_ptr makevdwreader(uint32_t ofs, uint32_t size)
    {
        std::vector<uint8_t> vdwkey= {'d', 'w', 'v' };
        return ReadWriter_ptr(new xorreader(vdwkey, getptr(ofs), getptr(ofs)+size));
    }
public:
    VdwFile(const std::vector<uint8_t>& M, const uint8_t* first, const uint8_t* last)
        : Section(M, 0, first, last), _cplen(0)
    {
        ReadWriter_ptr x= makevdwreader(0x2a, 20);

        uint32_t unk0=  x->read32le();
        uint32_t troot= x->read32le();
        uint32_t proot= x->read32le();
        uint32_t sroot= x->read32le();
        _cplen= x->read32le();

        printf("root: %d, %x, @%x:%x, copyrightlen=%x\n", unk0, troot, proot, sroot, _cplen);

        _root= RootSection_ptr(new RootSection(M,  troot, getptr(proot), getptr(proot+sroot)));

        uint32_t bofs, blen, btype;

        unsigned i=0;
        while (_root->getsection(i++, &bofs, &blen, &btype)) {
            switch (btype>>16) {
                case 2:
                    _blobs.push_back(BlobSection_ptr(new BlobSection(M, btype, getptr(bofs), getptr(bofs+blen))));
                    break;
                case 3:
                    _indices.push_back(IndexSection_ptr(new IndexSection(M, btype, getptr(bofs), getptr(bofs+blen))));
                    break;
                default:
                    printf("not handling section %08x/%08x: t%08x\n", bofs, blen, btype);
            }
        }
    }
    void dumpblobs()
    {
        for (auto i=_blobs.begin() ; i!=_blobs.end() ; ++i)
            (*i)->dumpinfo();
    }

    virtual void verifysection()
    {
        std::string copyright= ToString(std::Wstring((WCHAR*)getptr(0x3e), ((WCHAR*)getptr(0x3e))+_cplen));

        ReadWriter_ptr cpr= makexorreader(2*_cplen+0x3e, 2*_cplen);

        std::Wstring cp2;
        cpr->readutf16le(cp2, _cplen);

        if (ToString(cp2)!=copyright) {
            printf("copyright strings don't match\n");
            throw "error";
        }
        printf("%s\n", copyright.c_str());
    }

    // fulltext substring -> idxFulltextLemma
    // keyword substring -> idxTrefwoordLemma
};

int main(int argc, char**argv)
{
    if (argc<2) {
        printf("Usage: vdwreader <lang>\n");
        return 1;
    }
    std::string lang= argv[1];   argv++; argc--;
    auto ent= keymap.find(lang);
    if (ent==keymap.end()) {
        printf("unknown language\n");
        return 1;
    }

    try {
    MmapReader r(getpath(lang), MmapReader::readonly);

    if (r.size()<16) {
        printf("vdw too short\n");
        return 1;
    }
    std::vector<uint8_t> M(256);
        
    calcmd5key(ent->second, &M[0]);

    VdwFile vdw(M, r.begin(), r.end());

    vdw.verify();

    //vdw.dumpblobs();

    }
    catch(const char*msg)
    {
        printf("E: %s\n", msg);
    }
    printf("done\n");
    return 0;
}

