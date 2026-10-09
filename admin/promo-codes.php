<?php

declare(strict_types=1);

use INoon\Licensing\PromoCodes;

if (!isset($promoCodes) || !$promoCodes instanceof PromoCodes) {
    http_response_code(404);
    exit;
}

$promoRows = $promoCodes->list();
$perthNow = new DateTimeImmutable('now', new DateTimeZone('Australia/Perth'));
$defaultStart = $perthNow->format('Y-m-d\TH:i');
$defaultEnd = $perthNow->modify('+1 month')->format('Y-m-d\TH:i');
?>
<section class="hero">
    <div>
        <h2>Promo codes</h2>
        <p>Create free-license codes and control when each one can be redeemed.</p>
    </div>
</section>

<section class="panel">
    <div class="section-head"><h3>Add a promo code</h3></div>
    <form method="post" action="/admin/?tab=promos" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
        <input type="hidden" name="action" value="promo_create">
        <div class="form-grid">
            <div class="field">
                <label for="new-promo-code">Code</label>
                <input id="new-promo-code" name="code" type="text" maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_-]{2,63}" required placeholder="YOURCODE" autocapitalize="characters" spellcheck="false">
                <small>Letters, numbers, hyphens or underscores. Codes are not case-sensitive.</small>
            </div>
            <div class="field">
                <label for="new-promo-name">Display name</label>
                <input id="new-promo-name" name="display_name" type="text" maxlength="120" required placeholder="Community giveaway">
                <small>Used in the admin to identify this promotion.</small>
            </div>
            <div class="field full">
                <label for="new-promo-eyebrow">Page eyebrow</label>
                <input id="new-promo-eyebrow" name="page_eyebrow" type="text" maxlength="160" required placeholder="iNoon community giveaway">
            </div>
            <div class="field full">
                <label for="new-promo-title">Page title</label>
                <input id="new-promo-title" name="page_title" type="text" maxlength="200" required value="A free iNoon license for you.">
            </div>
            <div class="field full">
                <label for="new-promo-description">Page description</label>
                <textarea id="new-promo-description" name="page_description" maxlength="1000" required placeholder="Enter your name, email address, and promo code. We’ll email your personal license key to you."></textarea>
            </div>
            <div class="field">
                <label for="new-promo-start">Starts (Perth time)</label>
                <input id="new-promo-start" name="starts_at" type="datetime-local" value="<?= escapeHtml($defaultStart) ?>" required>
            </div>
            <div class="field">
                <label for="new-promo-end">Ends (Perth time)</label>
                <input id="new-promo-end" name="expires_at" type="datetime-local" value="<?= escapeHtml($defaultEnd) ?>" required>
            </div>
        </div>
        <div class="actions"><button class="button" type="submit">Add promo code</button></div>
    </form>
</section>

<div class="section-head" style="margin-top:30px">
    <h3>Current codes</h3>
    <span class="subtle">Removing a code stops new claims but keeps issued licenses and claim history.</span>
</div>

<?php if ($promoRows === []): ?>
    <section class="panel"><p class="subtle">No promo codes yet.</p></section>
<?php endif; ?>

<?php foreach ($promoRows as $row):
    $promoId = (int)$row['id'];
    $status = PromoCodes::status($row);
    $promoUrl = 'https://inoon.app/promo/?code=' . rawurlencode((string)$row['code']);
?>
    <section class="panel" style="margin-top:14px">
        <div class="section-head">
            <div>
                <h3 class="mono" style="font-size:18px;margin:0"><?= escapeHtml($row['code']) ?></h3>
                <span class="subtle"><?= escapeHtml($row['display_name']) ?> · <?= (int)$row['claim_count'] ?> license<?= (int)$row['claim_count'] === 1 ? '' : 's' ?> issued</span>
            </div>
            <span class="status <?= statusClass(strtolower($status)) ?>"><?= escapeHtml($status) ?></span>
        </div>
        <div class="key-line" style="margin:0 0 18px">
            <a href="<?= escapeHtml($promoUrl) ?>" target="_blank" rel="noopener noreferrer" class="mono"><?= escapeHtml($promoUrl) ?></a>
            <button class="copy-button" type="button" data-copy="<?= escapeHtml($promoUrl) ?>">Copy link</button>
        </div>
        <form method="post" action="/admin/?tab=promos" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
            <input type="hidden" name="action" value="promo_update">
            <input type="hidden" name="promo_id" value="<?= $promoId ?>">
            <div class="form-grid">
                <div class="field">
                    <label for="promo-name-<?= $promoId ?>">Display name</label>
                    <input id="promo-name-<?= $promoId ?>" name="display_name" type="text" maxlength="120" required value="<?= escapeHtml($row['display_name']) ?>">
                </div>
                <div class="field full">
                    <label for="promo-eyebrow-<?= $promoId ?>">Page eyebrow</label>
                    <input id="promo-eyebrow-<?= $promoId ?>" name="page_eyebrow" type="text" maxlength="160" required value="<?= escapeHtml($row['page_eyebrow']) ?>">
                </div>
                <div class="field full">
                    <label for="promo-title-<?= $promoId ?>">Page title</label>
                    <input id="promo-title-<?= $promoId ?>" name="page_title" type="text" maxlength="200" required value="<?= escapeHtml($row['page_title']) ?>">
                </div>
                <div class="field full">
                    <label for="promo-description-<?= $promoId ?>">Page description</label>
                    <textarea id="promo-description-<?= $promoId ?>" name="page_description" maxlength="1000" required><?= escapeHtml($row['page_description']) ?></textarea>
                </div>
                <div class="field">
                    <label for="promo-start-<?= $promoId ?>">Starts (Perth time)</label>
                    <input id="promo-start-<?= $promoId ?>" name="starts_at" type="datetime-local" value="<?= escapeHtml(PromoCodes::localInput((string)$row['starts_at'])) ?>" required>
                </div>
                <div class="field">
                    <label for="promo-end-<?= $promoId ?>">Ends (Perth time)</label>
                    <input id="promo-end-<?= $promoId ?>" name="expires_at" type="datetime-local" value="<?= escapeHtml(PromoCodes::localInput((string)$row['expires_at'])) ?>" required>
                </div>
                <label class="check">
                    <input type="checkbox" name="active" value="1" <?= (int)$row['active'] === 1 ? 'checked' : '' ?>>
                    <span><strong>Enabled</strong><span>Turn off to pause redemption.</span></span>
                </label>
            </div>
            <div class="actions"><button class="button" type="submit">Save promo</button></div>
        </form>
        <form method="post" action="/admin/?tab=promos" style="margin-top:10px" onsubmit="return confirm('Remove this promo code? Existing licences will remain valid.');">
            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
            <input type="hidden" name="action" value="promo_remove">
            <input type="hidden" name="promo_id" value="<?= $promoId ?>">
            <button class="button secondary" type="submit">Remove code</button>
        </form>
    </section>
<?php endforeach; ?>
