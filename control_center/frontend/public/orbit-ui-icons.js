/* Hermes Orbit 3.0 - local, fixed Lucide-style line icons for legacy
   read-only widgets that are rendered outside React. No dynamic markup,
   dependencies, network requests or privileged functionality.
   Lucide is MIT-licensed; third-party-notices.txt is served locally. */
(()=>{
 "use strict";
 const NS="http://www.w3.org/2000/svg";
 const shapes=Object.freeze({
  analytics:[
   ["path",{d:"M3 3v18h18"}],
   ["path",{d:"m7 16 4-5 4 3 5-7"}],
   ["path",{d:"M17 7h3v3"}]
  ],
  infrastructure:[
   ["rect",{x:"2",y:"3",width:"20",height:"8",rx:"2"}],
   ["rect",{x:"2",y:"13",width:"20",height:"8",rx:"2"}],
   ["path",{d:"M6 7h.01M6 17h.01"}],
   ["path",{d:"M10 7h8M10 17h8"}]
  ],
  quota:[
   ["path",{d:"M12 14l4-4"}],
   ["path",{d:"M3.34 19a10 10 0 1 1 17.32 0"}],
   ["path",{d:"M12 3v2M5.64 5.64l1.42 1.42M3 12h2M19 12h2M16.94 7.06l1.42-1.42"}]
  ],
  archive:[
   ["rect",{x:"3",y:"4",width:"18",height:"17",rx:"2"}],
   ["path",{d:"M3 9h18M8 2v4M16 2v4"}],
   ["path",{d:"m9 15 2 2 4-4"}]
  ]
 });
 function make(name,location="nav"){
  const specification=Object.hasOwn(shapes,name)?shapes[name]:null;
  if(!specification)return null;
  const holder=document.createElement("span");
  holder.className=location==="heading"?"orbit-panel-icon":"orbit-nav-icon";
  holder.setAttribute("aria-hidden","true");
  const svg=document.createElementNS(NS,"svg");
  for(const [attr,value] of Object.entries({
   xmlns:NS,width:"18",height:"18",viewBox:"0 0 24 24",
   fill:"none",stroke:"currentColor","stroke-width":"1.7",
   "stroke-linecap":"round","stroke-linejoin":"round","aria-hidden":"true"
  }))svg.setAttribute(attr,value);
  for(const [tag,attrs] of specification){
   const element=document.createElementNS(NS,tag);
   for(const [attr,value] of Object.entries(attrs))element.setAttribute(attr,value);
   svg.append(element);
  }
  holder.append(svg);
  return holder;
 }
 Object.defineProperty(window,"HermesOrbitIcons",{
  configurable:false,writable:false,value:Object.freeze({make})
 });
})();
