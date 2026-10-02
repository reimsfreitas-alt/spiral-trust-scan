"use strict";
module.exports = async function handler(req,res){
  if(req.method !== "GET") return res.status(405).json({ok:false,error:"method not allowed"});
  const url = new URL(req.url, "https://spiral-trust-scan.vercel.app");
  const receiptId = url.searchParams.get("r");
  const hash = url.searchParams.get("hash");
  const proof = receiptId
    ? "https://spiral-truth.vercel.app/r/"+encodeURIComponent(receiptId)+"?utm_source=badge&utm_medium=referral&utm_campaign=autopropulsor"
    : "https://spiral-truth.vercel.app/?utm_source=badge&utm_medium=referral&utm_campaign=autopropulsor";
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.setHeader("Access-Control-Allow-Origin","*");
  res.status(200).send(`<div style="border:1px solid #64FFDA;padding:12px;background:#0A0A0A;font-family:monospace;width:276px;color:#fff"><div style="color:#64FFDA;font-size:10px">VERIFICADO POR SPIRAL TRUTH</div><div style="font-size:12px;margin-top:7px">Recibo ${receiptId ? "#"+receiptId : "verificável"}${hash ? " · Hash: "+hash.slice(0,16)+"…" : ""}</div><a href="${proof}" target="_blank" rel="noopener" style="display:block;margin-top:9px;color:#aaa;font-size:10px">Ver prova → Gere o seu</a></div>`);
};