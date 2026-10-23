default:
    @just --list

check:
    mise run check
    mise run assure:inventory

assure: check
    mise run assure
    mise run mutants
