<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:fa="urn:fw-audit:network-audit:1"
  exclude-result-prefixes="fa">

  <xsl:output method="html" encoding="UTF-8" indent="yes"/>

  <xsl:template match="/">
    <html>
      <head>
        <meta charset="utf-8"/>
        <title>Network Audit Report</title>
        <style>
          body { font-family: system-ui, sans-serif; margin: 2rem; color: #212121; }
          h1, h2 { color: #1565c0; }
          table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
          th, td { border: 1px solid #ccc; padding: 0.5rem 0.75rem; text-align: left; }
          th { background: #e3f2fd; }
          tr.preferred td { background: #e8f5e9; border-left: 4px solid #2e7d32; }
          tr.risky td { background: #fff8e1; border-left: 4px solid #f9a825; }
          tr.unsafe td { background: #ffebee; border-left: 4px solid #c62828; }
          tr.unknown td { background: #f5f5f5; border-left: 4px solid #757575; }
          .cards { display: flex; gap: 1rem; flex-wrap: wrap; }
          .card { padding: 1rem 1.5rem; border-radius: 8px; min-width: 120px; }
          .card.preferred { background: #e8f5e9; border-left: 4px solid #2e7d32; }
          .card.risky { background: #fff8e1; border-left: 4px solid #f9a825; }
          .card.unsafe { background: #ffebee; border-left: 4px solid #c62828; }
          .card.unknown { background: #f5f5f5; border-left: 4px solid #757575; }
          .severity-critical { color: #c62828; font-weight: bold; }
          .severity-high { color: #e65100; font-weight: bold; }
          .severity-medium { color: #f9a825; }
          .meta { color: #616161; font-size: 0.9rem; }
        </style>
      </head>
      <body>
        <h1>Network Audit Report</h1>
        <p class="meta">
          Generated: <xsl:value-of select="/fa:NetworkAuditReport/@generatedAt"/>
          | Tool: <xsl:value-of select="/fa:NetworkAuditReport/@toolVersion"/>
        </p>

        <h2>Summary</h2>
        <div class="cards">
          <xsl:for-each select="/fa:NetworkAuditReport/fa:ExecutiveSummary/fa:Count">
            <div class="card">
              <xsl:attribute name="class">card <xsl:value-of select="@classification"/></xsl:attribute>
              <strong><xsl:value-of select="@classification"/></strong><br/>
              <xsl:value-of select="."/>
            </div>
          </xsl:for-each>
        </div>

        <h2>Compliance Mapping</h2>
        <table>
          <tr><th>Framework</th><th>ID</th><th>Status</th><th>Note</th></tr>
          <xsl:for-each select="/fa:NetworkAuditReport/fa:ComplianceMapping/fa:Framework">
            <xsl:variable name="fw" select="@name"/>
            <xsl:for-each select="fa:Safeguard | fa:Control">
              <tr>
                <td><xsl:value-of select="$fw"/></td>
                <td><xsl:value-of select="@id"/></td>
                <td><xsl:value-of select="@status"/></td>
                <td><xsl:value-of select="."/></td>
              </tr>
            </xsl:for-each>
          </xsl:for-each>
        </table>

        <h2>Flows / Listeners</h2>
        <table>
          <tr>
            <th>ID</th><th>Classification</th><th>Server</th><th>Zone</th>
            <th>Protocol</th><th>Port</th><th>Service</th>
          </tr>
          <xsl:for-each select="/fa:NetworkAuditReport/fa:Flows/fa:Flow">
            <tr>
              <xsl:attribute name="class"><xsl:value-of select="@classification"/></xsl:attribute>
              <td><xsl:value-of select="@id"/></td>
              <td><xsl:value-of select="@classification"/></td>
              <td><xsl:value-of select="fa:Server/@hostRef"/></td>
              <td><xsl:value-of select="fa:Server/@zone"/></td>
              <td><xsl:value-of select="fa:Service/@protocol"/></td>
              <td><xsl:value-of select="fa:Service/@port"/></td>
              <td><xsl:value-of select="fa:Service/@name"/></td>
            </tr>
          </xsl:for-each>
        </table>

        <h2>Findings</h2>
        <table>
          <tr><th>Severity</th><th>Code</th><th>Host</th><th>Detail</th></tr>
          <xsl:for-each select="/fa:NetworkAuditReport/fa:Findings/fa:Finding">
            <tr>
              <td>
                <span>
                  <xsl:attribute name="class">severity-<xsl:value-of select="@severity"/></xsl:attribute>
                  <xsl:value-of select="@severity"/>
                </span>
              </td>
              <td><xsl:value-of select="@code"/></td>
              <td><xsl:value-of select="@hostRef"/></td>
              <td><xsl:value-of select="."/></td>
            </tr>
          </xsl:for-each>
        </table>

        <h2>Ruleset Artifacts</h2>
        <ul>
          <xsl:for-each select="/fa:NetworkAuditReport/fa:RulesetArtifacts/fa:Artifact">
            <li>
              <xsl:value-of select="@platform"/> (<xsl:value-of select="@format"/>):
              <code><xsl:value-of select="@path"/></code>
              — <xsl:value-of select="@ruleCount"/> rules, defaultDeny=<xsl:value-of select="@defaultDeny"/>
            </li>
          </xsl:for-each>
        </ul>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
