"""Focused callback cohort; original provider385 remains separately mandatory."""
def cohort():
    rows=[]
    forms=[(k,w) for k in (2,3) for w in (16,32,64)]+[(4,64)]
    def add(name,kind=2,width=64,reg=0,control=0,layout=0,status=0,cf0=False,df=False,nested=False):
        rows.append(dict(name=name,args=[2,kind,width,reg,control,layout,0],status=status,
                         cf0=cf0,df=df,nested=nested))
    for k,w in forms:
        for r in (0,15):add(f'named-{k}-{w}-{r}',k,w,r,cf0=k==3,df=r==15)
    for k,w in forms:add(f'cross-{k}-{w}',k,w,8,layout=1,cf0=k==3)
    for k,w in forms:add(f'pre-refused-rsp-{k}-{w}',k,w,4,status=7)
    for control,status in ((1,3),(3,2),(4,2),(9,2),(19,4),(21,4),(25,4),(28,1),(45,2),(48,2)):
        add('pre-refused-'+str(control),control=control,status=status)
    for control in (13,14,15,16,17,18,32):
        add('bad-result-'+str(control),width=16 if control==15 else 64,control=control,status=9)
    add('returned-callback-failure',control=49,status=9)
    add('null-callback',control=51,status=1)
    add('alternate-rdrand-cf0',control=53,cf0=True,df=True)
    add('alternate-rdseed-cf1',kind=3,control=54,df=True)
    add('actual-nested-callback-fetch',control=50,nested=True)
    add('actual-nested-callback-fetch-cross-df',control=50,layout=1,df=True,nested=True)
    assert len(rows)==51 and len({r['name'] for r in rows})==51
    return rows
