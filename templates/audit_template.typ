// templates/audit_template.typ

// =====================================================================
// TRANSVINA EDGE SHIELD - TYPST LAYOUT ENGINE
// =====================================================================

#set page(
  paper: "a4", 
  margin: 1.5cm,
  footer: [
    #align(right)[
      #text(size: 9pt, style: "italic", fill: luma(100))[
        CONFIDENTIAL REPORT - Generated dynamically by the Transvina IPv6-Audit Engine.
      ]
    ]
  ]
)
#set text(font: "Roboto", size: 10pt)

// 1. Ingest the Data injected dynamically from Rust memory
#let dossier = json("dossier.json")

// 2. Document Header
#align(center)[
  #image("logo.png", width: 50%)
  
  #v(1em)
  #text(size: 24pt, weight: "bold")[Transvina Edge Shield] \
  #text(size: 14pt, style: "italic")[Enterprise IPv6 Readiness Audit]
]
#v(2em)

// 3. The Executive Summary Table
#table(
  columns: (4fr, 2fr, 2fr, 2fr, 8fr),
  align: horizon,
  fill: (col, row) => if row == 0 { luma(230) } else { white },
  stroke: 0.5pt + luma(150),
  
  // Table Headers
  [*Target Domain*], [*Web IPv6*], [*MX IPv6*], [*NS IPv6*], [*Executive Diagnosis*],

  // 4. Data Iteration Loop
  // We loop over the JSON array and map the booleans to PASS/FAIL statuses
  ..dossier.map(record => {
    let web_status = if record.web_ipv6_ready and record.web_ipv6_reachable {
      "PASS"
    } else if record.web_ipv6_ready {
      "DNS ONLY"
    } else {
      "FAIL"
    }
    
    let mx_status = if record.mx_ipv6_ready { "PASS" } else { "FAIL" }
    let ns_status = if record.ns_ipv6_ready { "PASS" } else { "FAIL" }

    (
      record.domain, 
      web_status, 
      mx_status, 
      ns_status, 
      record.vulnerability_status
    )
  }).flatten()
)

#v(3em)

// 5. The Evidence Appendix (Waterfall Charts)
// We check if ANY record contains the penalty key AND it's greater than 0
#let has_penalties = dossier.any(record => 
  "fallback_penalty_ms" in record and type(record.fallback_penalty_ms) == int and record.fallback_penalty_ms > 0
)

#if has_penalties [
  #text(size: 16pt, weight: "bold")[Architectural Evidence: HEv3 Fallback Penalties]
  #v(1em)

  // Loop through only the records that suffered a penalty
  #for record in dossier {
    // Safely check for the key's existence first, then evaluate its value
    if "fallback_penalty_ms" in record and type(record.fallback_penalty_ms) == int and record.fallback_penalty_ms > 0 {
      
      // We injected the image with the filename: "aws_amazon_com_waterfall.png"
      let safe_domain = record.domain.replace(".", "_")
      let img_path = safe_domain + "_waterfall.png"

      text(size: 12pt, style: "italic")[Target: #record.domain]
      v(0.5em)

      // Inject the dynamically generated plotters chart
      image(img_path, width: 80%)
      v(2em)
    }
  }
]
