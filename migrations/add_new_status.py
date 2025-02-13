from app import db, Report

def upgrade():
    """Atualiza os status existentes e adiciona os novos"""
    
    # Mapeia os status antigos para os novos
    status_mapping = {
        'Pendente': 'Em Análise',
        'Em Progresso': 'Em Andamento',
        'Concluído': 'Resolvido',
        'Cancelado': 'Cancelado'
    }
    
    try:
        reports = Report.query.all()
        for report in reports:
            if report.status in status_mapping:
                report.status = status_mapping[report.status]
        
        db.session.commit()
        print("Status atualizados com sucesso!")
        
    except Exception as e:
        print(f"Erro ao atualizar status: {str(e)}")
        db.session.rollback()

if __name__ == '__main__':
    upgrade() 