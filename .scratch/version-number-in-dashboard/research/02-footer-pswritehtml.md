# Footer Placement in PSWriteHTML

**Ticket:** [Footer placement in PSWriteHTML](../issues/02-footer-pswritehtml.md)  
**Status:** Research Complete  
**Date:** 2026-08-03

## Summary

PSWriteHTML provides the `New-HTMLFooter` cmdlet for adding footer content. Text alignment is controlled via the `-Alignment` parameter of `New-HTMLText`. For right-aligned footer text, use `New-HTMLText -Alignment right` inside `New-HTMLFooter`. The footer renders as a semantic `<footer>` tag at the end of the document body.

## Findings

### New-HTMLFooter command

Source: [EvotecIT/PSWriteHTML Public/New-HTMLFooter.ps1](https://github.com/EvotecIT/PSWriteHTML/blob/master/Public/New-HTMLFooter.ps1)

```powershell
New-HTMLFooter [[-HTMLContent] <scriptblock>]
```

- Optional building block inside `New-HTML`.
- Renders as `<footer>` at the end of the document body.

### Text alignment

Source: [EvotecIT/PSWriteHTML Public/New-HTMLText.ps1](https://github.com/EvotecIT/PSWriteHTML/blob/master/Public/New-HTMLText.ps1)

`New-HTMLText` accepts `-Alignment` with values `left`, `center`, `right`, `justify`. For bottom-right placement, use `-Alignment right`.

### Recommended usage

```powershell
New-HTML -TitleText 'Dashboard' -FilePath 'out.html' {
    # ... tabs and content ...
    New-HTMLFooter {
        New-HTMLText -Text "Locksmith 2 $versionString" -Alignment right -Color '#666' -FontSize 12
    }
}
```

### Interaction with -Online

The `-Online` switch only affects whether CSS/JS are loaded from CDN or embedded. It does not affect footer rendering.

### Fixed bottom-right corner vs. end-of-page footer

`New-HTMLFooter` places the footer at the end of the document in normal flow. If a fixed viewport bottom-right corner is required, custom CSS (`position: fixed; bottom: 10px; right: 10px;`) would be needed. The user's request says "bottom-right in the footer", which is satisfied by right-aligning text inside `New-HTMLFooter`.

## Recommendation

Add a `New-HTMLFooter` block at the end of the `New-HTML` script block, containing `New-HTMLText -Text "Locksmith 2 $versionString" -Alignment right -Color '#666' -FontSize 12`.

## Sources

- PSWriteHTML source: `New-HTMLFooter.ps1`, `New-HTMLText.ps1`, `New-HTML.ps1`.
- PSWriteHTML examples: `Example34-HeaderMainFooter`.
- Installed module: `c:\Users\Administrator\Documents\PowerShell\Modules\PSWriteHTML\1.41.0\PSWriteHTML.psd1`.
