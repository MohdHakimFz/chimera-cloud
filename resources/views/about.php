<section class="about-hero">
    <div class="about-statement">
        <p class="eyebrow">Platform architecture</p>
        <h1>Security controls should remain understandable.</h1>
        <p>CHIMERA is a bounded academic security platform. Legitimate workflows, security observation, synthetic deception, and research modules remain deliberately separated.</p>
    </div>
    <aside class="principle-index" aria-label="Architecture principles">
        <div><span>Principle</span><strong>Observe without overexposing</strong></div>
        <div><span>Control</span><strong>Authorization stays authoritative</strong></div>
        <div><span>Research</span><strong>Vulnerability state stays isolated</strong></div>
    </aside>
</section>

<section class="architecture-section" aria-labelledby="architecture-title">
    <div class="architecture-heading">
        <h2 id="architecture-title">Four boundaries. One coherent system.</h2>
        <p>The platform connects evidence where useful and separates control where safety requires it.</p>
    </div>
    <div class="architecture-map">
        <article class="architecture-node node-application">
            <span>PROTECTED APPLICATION</span><h3>Legitimate work comes first</h3>
            <p>Authentication, role controls, CSRF validation, document ownership, integrity checks, and private storage.</p>
            <ul><li>Standard users own their workflows</li><li>Administrative roles stay server-controlled</li></ul>
        </article>
        <article class="architecture-node node-operations">
            <span>SECURITY OPERATIONS</span><h3>Events become explainable evidence</h3>
            <p>Normalized telemetry feeds deterministic contributors, bounded scores, session assessments, and read-only analytics.</p>
            <ul><li>No automatic account mutation</li><li>No hidden scoring feedback loop</li></ul>
        </article>
        <article class="architecture-node node-deception">
            <span>SYNTHETIC DECEPTION</span><h3>Response without collateral change</h3>
            <p>Decoys, honeytokens, and adaptive profiles consume threat classification without altering legitimate authorization.</p>
            <ul><li>Synthetic data only</li><li>Secret marker material stays private</li></ul>
        </article>
        <article class="architecture-node node-lab">
            <span>CONTROLLED RESEARCH LAB</span><h3>Isolated and disabled by default</h3>
            <p>Academic modules are separately gated and remain outside ordinary user, document, deception, and scoring flows.</p>
        </article>
    </div>
</section>

<section class="marketing-section assurance-section" aria-labelledby="assurance-title">
    <div class="assurance-manifesto"><h2 id="assurance-title">What the platform refuses to blur.</h2><p>Good security design is as much about restraint as detection.</p></div>
    <div class="assurance-list">
        <article><strong>Scoring does not become authorization.</strong><p>Threat assessment observes and classifies. It does not assign roles, suspend users, or rewrite document ownership.</p></article>
        <article><strong>Deception does not become real infrastructure.</strong><p>Synthetic surfaces cannot execute commands, expose backups, or mutate legitimate application data.</p></article>
        <article><strong>Analytics does not become a data leak.</strong><p>Presentation and export boundaries minimize metadata and exclude private source-correlation fields.</p></article>
        <article><strong>Research does not become production behavior.</strong><p>The vulnerability LAB stays controlled, isolated, Security Admin gated, and disabled by default.</p></article>
    </div>
</section>

<section class="about-cta">
    <div><span>PROTECTED WORKSPACE</span><h2>Ready to see the application layer?</h2><p>Registration creates a standard User account. Administrative roles are never accepted from request input.</p></div>
    <div class="about-cta-actions"><a class="button button-primary" href="<?= e(url('/register')) ?>">Create account</a><a class="button button-secondary" href="<?= e(url('/login')) ?>">Sign in</a></div>
</section>
