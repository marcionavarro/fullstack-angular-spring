package com.example.algamoney.api.repository.filter;

import java.time.LocalDate;

public class LancamentoFilter {

	private String descricao;	
	private LocalDate dataVencimento;
	private LocalDate dataVencimentoAte;
	
	public String getDescricao() {
		return descricao;
	}
	
	public void setDescricao(String descricao) {
		this.descricao = descricao;
	}
	public LocalDate getDataVencimento() {
		return dataVencimento;
	}
	public void setDataVencimento(LocalDate dataVencimento) {
		this.dataVencimento = dataVencimento;
	}
	public LocalDate getDataVencimentoAte() {
		return dataVencimentoAte;
	}
	public void setDataVencimentoAte(LocalDate dataVencimentoAte) {
		this.dataVencimentoAte = dataVencimentoAte;
	}
}
