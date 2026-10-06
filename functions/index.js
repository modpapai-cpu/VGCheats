
const {onCall, HttpsError} = require("firebase-functions/v2/https");
const {defineSecret} = require("firebase-functions/params");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const Razorpay = require("razorpay");

admin.initializeApp();
const db = admin.database();

const OWNER_EMAILS = defineSecret("OWNER_EMAILS");
const RAZORPAY_KEY_ID = defineSecret("RAZORPAY_KEY_ID");
const RAZORPAY_KEY_SECRET = defineSecret("RAZORPAY_KEY_SECRET");

const ROOT = "vgcheats";
const accountsRef = () => db.ref(`${ROOT}/accounts`);
const userRef = uid => db.ref(`${ROOT}/users/${uid}`);
const ordersRef = uid => db.ref(`${ROOT}/orders/${uid}`);
const publicRef = key => db.ref(`${ROOT}/public/${key}`);
const keyPoolRef = (pid,idx) => db.ref(`${ROOT}/secure/keypool/${pid}/${idx}`);

const DEFAULT_CATALOG = {
  "1":[399,649,999,1799],
  "2":[249,399,599,1099],
  "3":[129,199,299,549],
  "4":[599,949,1499,2699],
  "5":[329,529,799,1449],
  "6":[799,1299,1999,3599]
};

function clean(s){ return String(s||"").trim(); }
function accountKey(username){ return Buffer.from(clean(username).toLowerCase()).toString("base64url"); }
function ownerEmails(){
  return clean(OWNER_EMAILS.value()).split(",").map(x=>x.trim().toLowerCase()).filter(Boolean);
}
function requireAuth(req){
  if(!req.auth) throw new HttpsError("unauthenticated","Firebase login required.");
}
function isOwner(req){
  return !!(req.auth && req.auth.token && req.auth.token.role === "owner");
}
function isAdmin(req){
  return !!(req.auth && req.auth.token && ["owner","admin"].includes(req.auth.token.role));
}
function requireOwner(req){ requireAuth(req); if(!isOwner(req)) throw new HttpsError("permission-denied","Owner permission required."); }
function requireAdmin(req){ requireAuth(req); if(!isAdmin(req)) throw new HttpsError("permission-denied","Admin permission required."); }

async function accountByUsername(username){
  const s=await accountsRef().child(accountKey(username)).get();
  return s.exists()?s.val():null;
}
async function accountByUid(uid){
  const s=await accountsRef().orderByChild("uid").equalTo(uid).limitToFirst(1).get();
  if(!s.exists()) return null;
  let out=null;s.forEach(c=>{out=c.val();});
  return out;
}
async function setClaims(uid,role,extra={}){
  await admin.auth().setCustomUserClaims(uid,{role,...extra});
}
function safeUser(a,wallet=0){
  if(!a)return null;
  return {uid:a.uid,u:a.u,username:a.u,email:a.email||"",role:a.role||"public",off:+a.off||0,
    blocked:!!a.blocked,freePanels:Array.isArray(a.freePanels)?a.freePanels:[],wallet:+wallet||0};
}

async function getMyAccount(req){
  requireAuth(req);
  const token=req.auth.token||{};
  if(token.role==="owner"){
    const email=(req.auth.token.email||"").toLowerCase();
    return {uid:req.auth.uid,u:"Owner",email,role:"owner",off:0,blocked:false,freePanels:[],wallet:0};
  }
  return accountByUid(req.auth.uid);
}

async function priceFor(pid,planIdx,account){
  pid=String(pid);planIdx=+planIdx||0;
  let rates = null;
  const rs=await publicRef("vg_rates").get();
  if(rs.exists() && rs.val() && rs.val()[pid]) rates=rs.val()[pid];
  if(!rates){
    const arr=DEFAULT_CATALOG[pid];
    if(!arr || arr[planIdx]===undefined) throw new HttpsError("not-found","Plan not found.");
    const labels=["7 Days","15 Days","30 Days","60 Days"];
    let price=arr[planIdx];
    const off=Math.min(90,Math.max(0,+account.off||0));
    if(off) price=Math.round(price*(100-off)/100);
    return {price,label:labels[planIdx]||("Plan "+(planIdx+1))};
  }
  const r=rates[planIdx];
  if(!r) throw new HttpsError("not-found","Plan not found.");
  let price=+r.price||0;
  const off=Math.min(90,Math.max(0,+account.off||0));
  if(off) price=Math.round(price*(100-off)/100);
  return {price,label:r.label||("Plan "+(planIdx+1))};
}

async function takeKeys(pid,idx,qty){
  qty=Math.max(1,Math.min(100,+qty||1));
  const ref=keyPoolRef(pid,idx);
  let taken=null;
  const tx=await ref.transaction(cur=>{
    cur=cur||{keys:[],file:""};
    const keys=Array.isArray(cur.keys)?cur.keys.slice():[];
    if(keys.length<qty) return;
    taken=keys.splice(0,qty);
    return {...cur,keys};
  });
  if(!tx.committed || !taken) throw new HttpsError("failed-precondition","Not enough keys available.");
  const v=tx.snapshot.val()||{};
  return {keys:taken,file:v.file||""};
}
async function putKeysBack(pid,idx,keys,file){
  const ref=keyPoolRef(pid,idx);
  await ref.transaction(cur=>{
    cur=cur||{keys:[],file:file||""};
    const old=Array.isArray(cur.keys)?cur.keys:[];
    return {keys:[...keys,...old],file:cur.file||file||""};
  });
}
function orderId(prefix="VG"){
  return prefix+Date.now().toString(36).toUpperCase()+crypto.randomBytes(3).toString("hex").toUpperCase();
}
async function saveOrder(o){
  await ordersRef(o.uid).child(o.id).set(o);
  return o;
}
async function allOrderEntries(){
  const s=await db.ref(`${ROOT}/orders`).get();
  const out=[];
  if(s.exists()) s.forEach(userNode=>userNode.forEach(o=>out.push(o.val())));
  return out;
}
async function findOrder(id){
  const s=await db.ref(`${ROOT}/orders`).get();
  let found=null;
  if(s.exists()) s.forEach(userNode=>userNode.forEach(o=>{if(o.key===id || o.val().id===id) found=o.val();}));
  return found;
}

exports.loginWithUsername = onCall(async req=>{
  const username=clean(req.data?.username), password=clean(req.data?.password);
  if(!username||!password) throw new HttpsError("invalid-argument","Username and password are required.");
  const a=await accountByUsername(username);
  if(!a) throw new HttpsError("not-found","Account not found.");
  if(a.blocked) throw new HttpsError("permission-denied","Your ID is blocked.");
  if(!(await bcrypt.compare(password,a.passwordHash||""))) throw new HttpsError("permission-denied","Wrong password.");
  await setClaims(a.uid,a.role||"public",{off:+a.off||0,blocked:!!a.blocked});
  const token=await admin.auth().createCustomToken(a.uid,{role:a.role||"public",off:+a.off||0});
  const w=(await userRef(a.uid).child("wallet").get()).val()||0;
  return {token,user:safeUser(a,w)};
});

exports.registerPublic = onCall(async req=>{
  const username=clean(req.data?.username), password=clean(req.data?.password), email=clean(req.data?.email).toLowerCase();
  if(!username||password.length<6||!email) throw new HttpsError("invalid-argument","Username, email and 6+ character password are required.");
  if(await accountByUsername(username)) throw new HttpsError("already-exists","Username already exists.");
  let authUser;
  try{ authUser=await admin.auth().createUser({email,password,displayName:username}); }
  catch(e){ throw new HttpsError("already-exists",e.message); }
  const a={uid:authUser.uid,u:username,email,role:"public",off:0,blocked:false,freePanels:[],createdAt:Date.now(),
    passwordHash:await bcrypt.hash(password,12)};
  await accountsRef().child(accountKey(username)).set(a);
  await userRef(authUser.uid).update({username,email,role:"public",wallet:0});
  await setClaims(authUser.uid,"public",{off:0,blocked:false});
  const token=await admin.auth().createCustomToken(authUser.uid,{role:"public",off:0});
  return {token,user:safeUser(a,0)};
});


function ownerOtpKey(email){
  return crypto.createHash("sha256").update(clean(email).toLowerCase()).digest("hex");
}
function hashOtp(email,otp){
  return crypto.createHash("sha256").update(ownerOtpKey(email)+":"+String(otp)).digest("hex");
}
async function getOrCreateOwnerAuth(email){
  try{
    return await admin.auth().getUserByEmail(email);
  }catch(e){
    if(e && e.code!=="auth/user-not-found") throw e;
    return await admin.auth().createUser({
      email,
      emailVerified:true,
      displayName:"Owner"
    });
  }
}

/* Server-side owner OTP.
   OWNER_EMAILS is a Firebase Secret containing one or more allowed owner emails.
   EmailJS sends the message; the OTP itself is generated and verified here. */
exports.sendOwnerOtp = onCall({secrets:[OWNER_EMAILS]}, async req=>{
  const email=clean(req.data?.email).toLowerCase();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    throw new HttpsError("invalid-argument","Valid email required.");
  if(!ownerEmails().includes(email))
    throw new HttpsError("permission-denied","This Gmail is not configured as an Owner email.");

  const ref=db.ref(`${ROOT}/secure/ownerOtp/${ownerOtpKey(email)}`);
  const existing=await ref.get();
  if(existing.exists() && (Date.now()-(existing.val().sentAt||0))<60000)
    throw new HttpsError("resource-exhausted","Please wait 60 seconds before requesting another OTP.");

  const otp=String(crypto.randomInt(100000,1000000));
  await ref.set({
    hash:hashOtp(email,otp),
    sentAt:Date.now(),
    expiresAt:Date.now()+10*60*1000,
    attempts:0
  });

  const response=await fetch("https://api.emailjs.com/api/v1.0/email/send",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      service_id:"service_v83whaa",
      template_id:"template_8xz1735",
      user_id:"adTWdxyIkZi72dEqN",
      template_params:{
        to_email:email,
        email,
        name:"VG CHEATS",
        otp,
        app_name:"VG CHEATS"
      }
    })
  });
  if(!response.ok){
    await ref.remove().catch(()=>{});
    const txt=await response.text().catch(()=>"");
    logger.error("EmailJS OTP send failed",txt);
    throw new HttpsError("internal","Unable to send OTP email. Check EmailJS service/template.");
  }

  return {ok:true,message:"📩 OTP sent to Gmail"};
});

exports.verifyOwnerOtp = onCall({secrets:[OWNER_EMAILS]}, async req=>{
  const email=clean(req.data?.email).toLowerCase();
  const otp=clean(req.data?.otp);
  if(!ownerEmails().includes(email))
    throw new HttpsError("permission-denied","This Gmail is not configured as an Owner email.");
  if(!/^\d{6}$/.test(otp))
    throw new HttpsError("invalid-argument","Enter the 6-digit OTP.");

  const ref=db.ref(`${ROOT}/secure/ownerOtp/${ownerOtpKey(email)}`);
  const snap=await ref.get();
  const data=snap.val();
  if(!data) throw new HttpsError("failed-precondition","OTP expired. Send a new OTP.");
  if(Date.now()>Number(data.expiresAt||0)){
    await ref.remove().catch(()=>{});
    throw new HttpsError("failed-precondition","OTP expired. Send a new OTP.");
  }
  const attempts=Number(data.attempts||0);
  if(attempts>=5){
    await ref.remove().catch(()=>{});
    throw new HttpsError("resource-exhausted","Too many wrong attempts. Send a new OTP.");
  }

  if(hashOtp(email,otp)!==data.hash){
    await ref.update({attempts:attempts+1});
    throw new HttpsError("permission-denied","Wrong OTP.");
  }

  await ref.remove().catch(()=>{});
  const au=await getOrCreateOwnerAuth(email);
  await admin.auth().updateUser(au.uid,{emailVerified:true});
  await setClaims(au.uid,"owner",{off:0,blocked:false});

  const token=await admin.auth().createCustomToken(au.uid,{role:"owner",off:0,blocked:false});
  await userRef(au.uid).update({username:"Owner",email,role:"owner",wallet:0});

  return {
    token,
    user:{uid:au.uid,u:"Owner",username:"Owner",email,role:"owner",off:0,blocked:false,freePanels:[],wallet:0}
  };
});

exports.ensureGoogleRole = onCall(async req=>{
  requireAuth(req);
  const email=clean(req.auth.token.email).toLowerCase();
  if(!email) throw new HttpsError("permission-denied","Google account has no email.");
  let a=null, role="public";
  if(ownerEmails().includes(email)){
    role="owner";
    a={uid:req.auth.uid,u:"Owner",email,role:"owner",off:0,blocked:false,freePanels:[]};
    await userRef(req.auth.uid).update({username:"Owner",email,role:"owner"});
    await setClaims(req.auth.uid,"owner");
  }else{
    a=await accountByUid(req.auth.uid);
    if(!a){
      const s=await accountsRef().orderByChild("email").equalTo(email).limitToFirst(1).get();
      if(s.exists()) s.forEach(c=>{a=c.val();});
    }
    if(!a) throw new HttpsError("permission-denied","This Gmail is not registered. Ask Owner to add it.");
    if(a.blocked) throw new HttpsError("permission-denied","Your ID is blocked.");
    role=a.role||"public";
    await setClaims(req.auth.uid,role,{off:+a.off||0,blocked:false});
  }
  const w=(await userRef(req.auth.uid).child("wallet").get()).val()||0;
  return {user:safeUser(a,w)};
});

exports.getMyProfile = onCall(async req=>{
  requireAuth(req);
  const a=await getMyAccount(req);
  if(!a) throw new HttpsError("not-found","Profile not found.");
  const w=(await userRef(req.auth.uid).child("wallet").get()).val()||0;
  return {user:safeUser(a,w)};
});

exports.createManagedUser = onCall(async req=>{
  requireOwner(req);
  const d=req.data||{}, username=clean(d.username), password=clean(d.password);
  const role=["admin","reseller"].includes(d.role)?d.role:"reseller";
  const email=clean(d.email).toLowerCase();
  if(!username||password.length<6) throw new HttpsError("invalid-argument","Username and 6+ character password are required.");
  if(await accountByUsername(username)) throw new HttpsError("already-exists","Username already exists.");
  const authEmail=email || `${accountKey(username)}@accounts.vgcheats.local`;
  let au;
  try{au=await admin.auth().createUser({email:authEmail,password,displayName:username});}
  catch(e){throw new HttpsError("already-exists",e.message);}
  const a={uid:au.uid,u:username,email:email,role,off:Math.min(90,Math.max(0,+d.off||0)),blocked:false,
    freePanels:Array.isArray(d.freePanels)?d.freePanels.map(String):[],createdAt:Date.now(),
    passwordHash:await bcrypt.hash(password,12)};
  await accountsRef().child(accountKey(username)).set(a);
  await userRef(au.uid).set({username,email,role,wallet:0});
  await setClaims(au.uid,role,{off:a.off,blocked:false});
  return {user:safeUser(a,0)};
});

exports.syncManagedUsers = onCall(async req=>{
  requireOwner(req);
  const incoming=Array.isArray(req.data?.users)?req.data.users:[];
  const existingSnap=await accountsRef().get();
  const incomingKeys=new Set();
  for(const x of incoming){
    const username=clean(x.u); if(!username) continue;
    const key=accountKey(username); incomingKeys.add(key);
    let a=(await accountsRef().child(key).get()).val();
    let au=null;
    if(!a){
      const email=clean(x.email).toLowerCase() || `${key}@accounts.vgcheats.local`;
      try{au=await admin.auth().createUser({email,password:clean(x.p)||crypto.randomBytes(9).toString("base64url"),displayName:username});}
      catch(e){logger.error("create managed user",e);continue;}
      a={uid:au.uid,u:username,email:clean(x.email).toLowerCase(),role:["admin","reseller","public"].includes(x.role)?x.role:"public",
        off:Math.min(90,Math.max(0,+x.off||0)),blocked:!!x.blocked,freePanels:Array.isArray(x.freePanels)?x.freePanels:[],createdAt:Date.now(),
        passwordHash:""};
    }else{
      au=await admin.auth().getUser(a.uid);
      if(clean(x.p)){
        await admin.auth().updateUser(a.uid,{password:clean(x.p)});
        a.passwordHash=await bcrypt.hash(clean(x.p),12);
      }
      const newEmail=clean(x.email).toLowerCase();
      const targetEmail=newEmail || `${key}@accounts.vgcheats.local`;
      if(au.email!==targetEmail){try{await admin.auth().updateUser(a.uid,{email:targetEmail});}catch(e){}}
      a.email=newEmail;
      a.role=["admin","reseller","public"].includes(x.role)?x.role:"public";
      a.off=Math.min(90,Math.max(0,+x.off||0));a.blocked=!!x.blocked;
      a.freePanels=Array.isArray(x.freePanels)?x.freePanels.map(String):[];
    }
    await accountsRef().child(key).set(a);
    await userRef(a.uid).update({username:a.u,email:a.email,role:a.role});
    await setClaims(a.uid,a.role,{off:a.off,blocked:a.blocked});
  }
  if(existingSnap.exists()){
    const dels=[];
    existingSnap.forEach(c=>{
      if(!incomingKeys.has(c.key)){
        const a=c.val();
        if(a&&a.uid) dels.push(admin.auth().deleteUser(a.uid).catch(()=>{}));
        dels.push(accountsRef().child(c.key).remove());
        dels.push(userRef(a.uid).remove());
      }
    });
    await Promise.all(dels);
  }
  return {ok:true};
});

exports.listManagedUsers = onCall(async req=>{
  requireOwner(req);
  const s=await accountsRef().get(),users=[];
  if(s.exists()) for(const c of Object.values(s.val())){
    const w=(await userRef(c.uid).child("wallet").get()).val()||0;
    users.push({...safeUser(c,w),p:""});
  }
  return {users};
});

exports.setWalletBalance = onCall(async req=>{
  requireOwner(req);
  const a=await accountByUsername(req.data?.username);
  if(!a) throw new HttpsError("not-found","User not found.");
  const balance=Math.max(0,Math.floor(+req.data?.balance||0));
  await userRef(a.uid).child("wallet").set(balance);
  return {ok:true,balance};
});

exports.saveKeyPool = onCall(async req=>{
  requireOwner(req);
  const pid=clean(req.data?.pid),idx=+req.data?.planIdx||0;
  const keys=[...new Set((Array.isArray(req.data?.keys)?req.data.keys:[]).map(x=>String(x).trim()).filter(Boolean))];
  await keyPoolRef(pid,idx).set({keys,file:clean(req.data?.file)});
  return {ok:true};
});

exports.createManualOrder = onCall(async req=>{
  requireAuth(req);
  if(req.auth.token.role==="owner") throw new HttpsError("failed-precondition","Owner cannot place customer orders.");
  const a=await getMyAccount(req); if(!a) throw new HttpsError("not-found","Account not found.");
  const pid=clean(req.data?.pid),idx=+req.data?.planIdx||0,qty=Math.max(1,Math.min(20,+req.data?.qty||1));
  const pr=await priceFor(pid,idx,a);
  const p=await publicRef("vg_panelinfo").get(); const info=(p.val()||{})[pid]||{};
  const o={id:orderId(),uid:a.uid,user:a.u,pid,plan:pr.label,planIdx:idx,price:pr.price*qty,qty,panel:info.name||pid,
    ts:Date.now(),status:"pending",payment:"manual",keys:[],key:"",file:"",mobile:clean(req.data?.mobile)};
  await saveOrder(o);return {order:o};
});

exports.createManualTopup = onCall(async req=>{
  requireAuth(req);
  const amount=Math.max(10,Math.floor(+req.data?.amount||0)); if(!amount) throw new HttpsError("invalid-argument","Invalid amount.");
  const a=await getMyAccount(req); if(!a) throw new HttpsError("not-found","Account not found.");
  const o={id:orderId("TP"),uid:a.uid,user:a.u,type:"topup",panel:"Wallet Top-up",plan:"Balance",price:amount,
    mobile:clean(req.data?.mobile),ts:Date.now(),status:"pending",payment:"manual",keys:[],key:"",file:""};
  await saveOrder(o);return {order:o};
});

function razorpay(){
  return new Razorpay({key_id:RAZORPAY_KEY_ID.value(),key_secret:RAZORPAY_KEY_SECRET.value()});
}
async function createRzpOrderForUser(req,isTopup){
  requireAuth(req);
  const a=await getMyAccount(req);if(!a)throw new HttpsError("not-found","Account not found.");
  let amount;
  let orderData;
  if(isTopup){
    amount=Math.max(10,Math.floor(+req.data?.amount||0))*100;
    orderData={type:"topup",amount};
  }else{
    const pid=clean(req.data?.pid),idx=+req.data?.planIdx||0,qty=Math.max(1,Math.min(20,+req.data?.qty||1));
    const pr=await priceFor(pid,idx,a); amount=pr.price*qty*100;
    const info=((await publicRef("vg_panelinfo").get()).val()||{})[pid]||{};
    orderData={pid,planIdx:idx,qty,panel:info.name||pid,plan:pr.label,price:pr.price*qty};
  }
  if(amount<=0)throw new HttpsError("invalid-argument","Invalid amount.");
  const rz=razorpay();
  const rzOrder=await rz.orders.create({amount,currency:"INR",receipt:orderId("RZ"),payment_capture:1});
  const id=orderId("ORD");
  const o={id,uid:a.uid,user:a.u,ts:Date.now(),status:"payment_pending",payment:"razorpay",
    razorpayOrderId:rzOrder.id,price:orderData.amount?orderData.amount/100:orderData.price,
    qty:orderData.qty||1,...orderData,keys:[],key:"",file:""};
  await saveOrder(o);
  return {orderId:rzOrder.id,keyId:RAZORPAY_KEY_ID.value(),amount:rzOrder.amount,name:(await publicRef("vg_site").get()).val()?.name||"VG CHEATS",order:o};
}
exports.createRazorpayOrder=onCall({secrets:[RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET]},req=>createRzpOrderForUser(req,false));
exports.createTopupRazorpayOrder=onCall({secrets:[RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET]},req=>createRzpOrderForUser(req,true));

async function verifyRzpSignature(orderId,paymentId,signature){
  const expected=crypto.createHmac("sha256",RAZORPAY_KEY_SECRET.value()).update(`${orderId}|${paymentId}`).digest("hex");
  const actual=Buffer.from(signature||"");
  const exp=Buffer.from(expected);
  return actual.length===exp.length && crypto.timingSafeEqual(exp,actual);
}
async function finalizeProductOrder(o){
  if(o.status==="approved") return o;
  const got=await takeKeys(o.pid,o.planIdx,o.qty||1);
  o.keys=got.keys;o.key=got.keys[0]||"";o.file=got.file||"";o.status="approved";o.verifiedAt=Date.now();
  await saveOrder(o); return o;
}
exports.verifyRazorpayPayment=onCall({secrets:[RAZORPAY_KEY_SECRET]},async req=>{
  requireAuth(req);
  const d=req.data||{};
  if(!d.razorpay_order_id||!d.razorpay_payment_id||!d.razorpay_signature) throw new HttpsError("invalid-argument","Incomplete Razorpay response.");
  if(!(await verifyRzpSignature(d.razorpay_order_id,d.razorpay_payment_id,d.razorpay_signature))) throw new HttpsError("permission-denied","Invalid payment signature.");
  const s=await db.ref(`${ROOT}/orders`).get();let o=null;
  if(s.exists()) s.forEach(un=>un.forEach(x=>{if(x.val().razorpayOrderId===d.razorpay_order_id)o=x.val();}));
  if(!o) throw new HttpsError("not-found","Payment order not found.");
  if(o.uid!==req.auth.uid) throw new HttpsError("permission-denied","This payment does not belong to you.");
  if(o.type==="topup"){
    const aRef=userRef(o.uid).child("wallet");
    await aRef.transaction(v=>(+(v||0))+(+o.price||0));
    o.status="approved";o.verifiedAt=Date.now();o.paymentId=d.razorpay_payment_id;await saveOrder(o);
    return {order:o};
  }
  o.paymentId=d.razorpay_payment_id;
  o.status="payment_verified";
  await saveOrder(o);
  try{o=await finalizeProductOrder(o);}catch(e){o.status="paid_pending_key";await saveOrder(o);throw e;}
  return {order:o};
});

exports.purchaseWithWallet=onCall(async req=>{
  requireAuth(req);
  const a=await getMyAccount(req);if(!a)throw new HttpsError("not-found","Account not found.");
  const pid=clean(req.data?.pid),idx=+req.data?.planIdx||0,qty=Math.max(1,Math.min(20,+req.data?.qty||1));
  const pr=await priceFor(pid,idx,a), total=pr.price*qty;
  const wref=userRef(a.uid).child("wallet");
  const tx=await wref.transaction(v=>{v=+(v||0);if(v<total)return;return v-total;});
  if(!tx.committed)throw new HttpsError("failed-precondition","Insufficient wallet balance.");
  let got;
  try{got=await takeKeys(pid,idx,qty);}catch(e){await wref.transaction(v=>(+(v||0))+total);throw e;}
  const info=((await publicRef("vg_panelinfo").get()).val()||{})[pid]||{};
  const o={id:orderId("WAL"),uid:a.uid,user:a.u,pid,plan:pr.label,planIdx:idx,price:total,qty,panel:info.name||pid,
    ts:Date.now(),status:"approved",payment:"wallet",keys:got.keys,key:got.keys[0]||"",file:got.file||""};
  await saveOrder(o);return {order:o};
});

exports.approveOrder=onCall(async req=>{
  requireOwner(req);
  const id=clean(req.data?.orderId),o=await findOrder(id);
  if(!o)throw new HttpsError("not-found","Order not found.");
  if(o.status==="approved")return {order:o};
  if(o.type==="topup"){
    await userRef(o.uid).child("wallet").transaction(v=>(+(v||0))+(+o.price||0));
    o.status="approved";o.approvedAt=Date.now();await saveOrder(o);return {order:o};
  }
  if(!["pending","payment_verified","payment_pending"].includes(o.status))throw new HttpsError("failed-precondition","Order cannot be approved.");
  const got=await takeKeys(o.pid,o.planIdx,o.qty||1);
  o.keys=got.keys;o.key=got.keys[0]||"";o.file=got.file||"";o.status="approved";o.approvedAt=Date.now();
  await saveOrder(o);return {order:o};
});
exports.rejectOrder=onCall(async req=>{
  requireOwner(req);
  const id=clean(req.data?.orderId),o=await findOrder(id);if(!o)throw new HttpsError("not-found","Order not found.");
  o.status="rejected";o.rejectedAt=Date.now();await saveOrder(o);return {order:o};
});
exports.deleteOrder=onCall(async req=>{
  requireOwner(req);
  const id=clean(req.data?.orderId),o=await findOrder(id);if(!o)throw new HttpsError("not-found","Order not found.");
  await ordersRef(o.uid).child(o.id).remove();return {ok:true};
});
exports.clearRejectedOrders=onCall(async req=>{
  requireOwner(req);
  const s=await db.ref(`${ROOT}/orders`).get(),tasks=[];
  if(s.exists())s.forEach(un=>un.forEach(x=>{if(x.val().status==="rejected")tasks.push(ordersRef(un.key).child(x.key).remove());}));
  await Promise.all(tasks);return {ok:true};
});
exports.listAllOrders=onCall(async req=>{
  requireAdmin(req);return {orders:await allOrderEntries()};
});
exports.savePublicData=onCall(async req=>{
  requireOwner(req);
  const key=clean(req.data?.key);if(!key)throw new HttpsError("invalid-argument","Key required.");
  const allowed=["vg_rates","vg_videos","vg_thumbs","vg_links","vg_custom_panels","vg_site","vg_panelinfo","vg_order"];
  if(!allowed.includes(key))throw new HttpsError("permission-denied","Public key not allowed.");
  const v=req.data?.value||null;
  if(key==="vg_site" && v) delete v.kaseller;
  await publicRef(key).set(v);return {ok:true};
});
